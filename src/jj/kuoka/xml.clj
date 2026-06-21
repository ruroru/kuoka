(ns jj.kuoka.xml
  (:require [clojure.xml :as cx]                  ; for emit only
            [clojure.data.xml :as dx]              ; for parse only
            [clojure.java.io :as io]
            [clojure.string :as str]))

(def dav-ns "DAV:")
(def dav-prefix "D")

(defn- dav-tag [local]
  (keyword (str dav-prefix ":" local)))

(defn- ns-attrs []
  {(keyword (str "xmlns:" dav-prefix)) dav-ns})

(defn element
  ([local content] (element local {} content))
  ([local attrs & content]
   {:tag (dav-tag local) :attrs (merge (ns-attrs) attrs)
    :content (remove nil? (flatten content))}))

(defn child-element
  ([local] {:tag (dav-tag local) :attrs {} :content ()})
  ([local attrs] {:tag (dav-tag local) :attrs attrs :content ()})
  ([local attrs & content]
   {:tag (dav-tag local) :attrs attrs :content (remove nil? (flatten content))}))

(defn text-el [local text]
  {:tag (dav-tag local) :attrs {} :content [(str text)]})

(defn- href-el [url] (text-el "href" url))
(defn status-el [msg] (text-el "status" msg))

(defn emit-xml [el] (with-out-str (cx/emit el)))

(defn- element->map
  "Convert a clojure.data.xml node.Element to {:tag :local-name :attrs {} :content [...]}"
  [el]
  {:tag     (keyword (name (:tag el)))
   :attrs   (into {} (for [[k v] (:attrs el)]
                      [(keyword (name k)) (str v)]))
   :content (mapv (fn [c]
                    (if (map? c)
                      (element->map c)
                      c))
                  (:content el))})

(defn- find-child [tag-kw element]
  (some #(when (= (:tag %) tag-kw) %) (:content element)))

(defn- find-children [tag-kw element]
  (filter #(= (:tag %) tag-kw) (:content element)))

(defn parse-xml-body
  "Parse XML from a Ring request. Extracts :body and parses with clojure.data.xml."
  [request]
  (when-let [body (:body request)]
    (try (element->map (dx/parse (io/input-stream body)))
         (catch Exception _ nil))))


(defn multi-status-body [responses]
  (emit-xml
    (element "multistatus" {}
             (for [[href props] responses]
               (child-element "response" {}
                              (href-el href)
                              (child-element "propstat" {}
                                             (child-element "prop" {} (flatten props))
                                             (status-el "HTTP/1.1 200 OK")))))))

(declare privilege-xml-el privilege-tree-xml ace-xml acl-restrictions-xml lock-entry-xml supportedlock-xml principal-xml)

(defn- resource-type-el [is-collection?]
  (child-element "resourcetype" {} (when is-collection? (child-element "collection"))))

(defn property-xml [prop-key prop-val]
  (case prop-key
    :dav/resourcetype             (resource-type-el (some? prop-val))
    :dav/getcontentlength         (text-el "getcontentlength" (str prop-val))
    :dav/getcontenttype           (text-el "getcontenttype" (str prop-val))
    :dav/getetag                  (text-el "getetag" (str prop-val))
    :dav/getlastmodified          (text-el "getlastmodified" (str prop-val))
    :dav/creationdate             (text-el "creationdate" (str prop-val))
    :dav/displayname              (text-el "displayname" (str (or prop-val "")))
    :dav/owner                    (child-element "owner" {} (when prop-val (href-el prop-val)))
    :dav/group                    (child-element "group" {} (when prop-val (href-el prop-val)))
    :dav/principal-URL            (child-element "principal-URL" {} (href-el (str prop-val)))
    :dav/alternate-URI-set        (child-element "alternate-URI-set" {} (map href-el prop-val))
    :dav/group-member-set         (child-element "group-member-set" {} (map href-el prop-val))
    :dav/group-membership         (child-element "group-membership" {} (map href-el prop-val))
    :dav/supported-privilege-set  (child-element "supported-privilege-set" {} (privilege-tree-xml prop-val))
    :dav/current-user-privilege-set (child-element "current-user-privilege-set" {}
                                                   (map privilege-xml-el prop-val))
    :dav/acl                      (child-element "acl" {} (map ace-xml prop-val))
    :dav/acl-restrictions         (acl-restrictions-xml prop-val)
    :dav/inherited-acl-set        (child-element "inherited-acl-set" {} (map href-el prop-val))
    :dav/principal-collection-set (child-element "principal-collection-set" {} (map href-el prop-val))
    :dav/lockdiscovery            (child-element "lockdiscovery" {} (map lock-entry-xml prop-val))
    :dav/supportedlock            (supportedlock-xml)
    (text-el (name prop-key) (str (or prop-val "")))))

(defn- privilege-xml-el [priv-kw]
  (child-element "privilege" {} (child-element (name priv-kw))))

(defn- build-privilege-tree-xml [all-nodes priv-key]
  (when-let [info (get all-nodes priv-key)]
    (child-element "supported-privilege" {}
                   (child-element "privilege" {} (child-element (name priv-key)))
                   (when (:abstract info) (child-element "abstract"))
                   (child-element "description" {(keyword "xml:lang") "en"} (:description info))
                   (map #(build-privilege-tree-xml all-nodes %) (:children info)))))

(defn- privilege-tree-xml [tree-seq]
  (let [by-priv (into {} (map (juxt :privilege identity) tree-seq))]
    (build-privilege-tree-xml by-priv :dav/all)))

(defn- ace-xml [ace]
  (child-element "ace" {}
                 (principal-xml (:principal ace))
                 (case (:type ace)
                   :grant (child-element "grant" {} (map privilege-xml-el (:privileges ace)))
                   :deny  (child-element "deny" {} (map privilege-xml-el (:privileges ace))))
                 (when (:protected? ace) (child-element "protected"))
                 (when (:inherited ace) (child-element "inherited" {} (href-el (:inherited ace))))))

(defn- principal-xml [principal]
  (child-element "principal" {}
                 (case (:type principal)
                   :all            (child-element "all")
                   :authenticated  (child-element "authenticated")
                   :unauthenticated (child-element "unauthenticated")
                   :self           (child-element "self")
                   :href           (href-el (:value principal))
                   :property       (child-element "property" {} (text-el (name (:value principal)) ""))
                   :invert         (child-element "invert" {} (principal-xml (:value principal)))
                   (href-el (str (:value principal))))))

(defn- acl-restrictions-xml [restrictions]
  (child-element "acl-restrictions" {}
                 (when (:grant-only? restrictions) (child-element "grant-only"))
                 (when (:no-invert? restrictions) (child-element "no-invert"))
                 (when (:deny-before-grant? restrictions) (child-element "deny-before-grant"))
                 (when (seq (:required-principals restrictions))
                   (for [rp (:required-principals restrictions)]
                     (child-element "required-principal" {} (principal-xml rp))))))

(defn lock-entry-xml [lock]
  (child-element "activelock" {}
                 (child-element "locktype" {} (child-element "write"))
                 (child-element "lockscope" {}
                                (if (= (:scope lock) :shared)
                                  (child-element "shared")
                                  (child-element "exclusive")))
                 (child-element "depth" {} (str (or (:depth lock) "infinity")))
                 (when (:owner lock) (child-element "owner" {} (href-el (:owner lock))))
                 (child-element "timeout" {} (str (:timeout lock)))
                 (child-element "locktoken" {} (href-el (:token lock)))))

(defn- supportedlock-xml []
  (child-element "supportedlock" {}
                 (child-element "lockentry" {}
                                (child-element "lockscope" {} (child-element "exclusive"))
                                (child-element "locktype" {} (child-element "write")))))

(defn error-body [resources-needed]
  (emit-xml
    (element "error" {}
             (child-element "need-privileges" {}
                            (for [[res p] resources-needed]
                              (child-element "resource" {}
                                             (href-el res)
                                             (privilege-xml-el p)))))))

(defn parse-propfind
  "Extract requested property names from a parsed PROPFIND body.
   Returns :allprop, :propname, or a seq of property keywords like [:dav/displayname]."
  [body-el]
  (when body-el
    (let [propfind (or (find-child :propfind body-el) body-el)
          prop     (some #(or (find-child :prop %) (find-child :propfind %)) (:content propfind))
          allprop  (some #(when (= (:tag %) :allprop) %) (:content (or prop propfind)))
          propname (some #(when (= (:tag %) :propname) %) (:content (or prop propfind)))]
      (cond
        allprop  :allprop
        propname :propname
        prop     (keep #(when (:tag %) (keyword "dav" (name (:tag %)))) (:content prop))
        :else    :allprop))))

(defn parse-proppatch
  "Parse a PROPPATCH request body. Returns {:set {prop-key val ...} :remove [prop-key ...]}"
  [body-el]
  (when body-el
    (let [pu        (or (find-child :propertyupdate body-el) body-el)
          set-el    (find-child :set pu)
          remove-el (find-child :remove pu)]
      {:set
       (when set-el
         (let [prop (find-child :prop set-el)]
           (into {} (for [child (:content prop) :when (:tag child)]
                      [(keyword "dav" (name (:tag child)))
                       (let [c (:content child)]
                         (if (and (seq c) (every? string? c)) (str/join c) (first c)))]))))
       :remove
       (when remove-el
         (let [prop (find-child :prop remove-el)]
           (keep #(when (:tag %) (keyword "dav" (name (:tag %)))) (:content prop))))})))

(defn- principal-data-from-el [el]
  (let [child (first (filter :tag (:content el)))]
    (when child
      (case (:tag child)
        :all            {:type :all}
        :authenticated  {:type :authenticated}
        :unauthenticated {:type :unauthenticated}
        :self           {:type :self}
        :href           {:type :href :value (first (:content child))}
        :property       {:type :property
                         :value (when-let [c (first (:content child))]
                                  (keyword "dav" (name (:tag c))))}
        {:type :href :value (first (:content child))}))))

(defn parse-acl-body
  "Parse an ACL method request body into a list of ACE data structures."
  [body-el]
  (when body-el
    (let [acl  (or (find-child :acl body-el) body-el)
          aces (find-children :ace acl)]
      (for [ace aces]
        (let [principal-el (find-child :principal ace)
              grant-el     (find-child :grant ace)
              deny-el      (find-child :deny ace)
              protected?   (boolean (find-child :protected ace))
              inherited-el (find-child :inherited ace)
              principal-data
              (when principal-el
                (let [child (first (filter :tag (:content principal-el)))]
                  (when child
                    (case (:tag child)
                      :all            {:type :all}
                      :authenticated  {:type :authenticated}
                      :unauthenticated {:type :unauthenticated}
                      :self           {:type :self}
                      :href           {:type :href :value (first (:content child))}
                      :property       {:type :property
                                       :value (when-let [c (first (:content child))]
                                                (keyword "dav" (name (:tag c))))}
                      :invert         {:type :invert :value (principal-data-from-el child)}
                      {:type :href :value (first (:content child))}))))
              privileges
              (let [el    (or grant-el deny-el)
                    privs (find-children :privilege el)]
                (set (map (fn [p]
                            (let [child (first (:content p))]
                              (keyword "dav" (name (:tag child)))))
                          privs)))
              inherited-href
              (when inherited-el
                (some-> (find-child :href inherited-el) :content first str))]
          {:type       (if deny-el :deny :grant)
           :principal  principal-data
           :privileges privileges
           :protected? protected?
           :inherited  inherited-href})))))

(defn parse-report-body
  "Parse a REPORT request body. Returns {:type ...} map."
  [body-el]
  (when body-el
    (let [root (or body-el {})
          tag  (:tag root)]
      (case tag
        :principal-property-search
        {:type :principal-property-search
         :search-spec (when-let [spec (find-child :property-search root)]
                        (into {} (for [prop (:content spec) :when (:tag prop)]
                                   [(keyword "dav" (name (:tag prop)))
                                    (let [c (:content prop)]
                                      (if (and (seq c) (every? string? c))
                                        (str/join c) (first c)))])))
         :prop (when-let [p (find-child :prop root)]
                 (keep #(when (:tag %) (keyword "dav" (name (:tag %)))) (:content p)))}

        :principal-search-property-set
        {:type :principal-search-property-set}

        :acl-principal-prop-set
        {:type :acl-principal-prop-set
         :prop (when-let [p (find-child :prop root)]
                 (keep #(when (:tag %) (keyword "dav" (name (:tag %)))) (:content p)))}

        :principal-match
        {:type :principal-match
         :principal-self (some-> (find-child :principal-property root)
                                 (find-child :principal-url))
         :prop (when-let [p (find-child :prop root)]
                 (keep #(when (:tag %) (keyword "dav" (name (:tag %)))) (:content p)))}

        {:type :unknown}))))
