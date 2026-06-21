(ns jj.kuoka.acl
  (:require [clojure.string :as str]
            [clojure.set :as set]))

(defonce ^:private privilege-tree
  {:dav/all
   {:abstract true
    :description "Any operation"
    :children #{:dav/read :dav/write :dav/read-acl :dav/write-acl
                :dav/read-current-user-privilege-set :dav/unlock}}

   :dav/read
   {:description "Read any object"
    :children #{:dav/read-acl :dav/read-current-user-privilege-set}}

   :dav/write
   {:abstract true
    :description "Write any object"
    :children #{:dav/write-properties :dav/write-content :dav/bind :dav/unbind}}

   :dav/write-properties {:description "Write properties"}
   :dav/write-content    {:description "Write resource content"}
   :dav/bind             {:description "Add a member to a collection"}
   :dav/unbind           {:description "Remove a member from a collection"}
   :dav/read-acl         {:description "Read the ACL"}
   :dav/read-current-user-privilege-set {:description "Read current user privilege set"}
   :dav/write-acl        {:description "Write the ACL"}
   :dav/unlock           {:description "Unlock a resource"}})

(defn- get-privilege-info [priv] (get privilege-tree priv))

(defn- abstract-privilege? [priv] (:abstract (get-privilege-info priv)))

(defn- all-privileges [] (set (keys privilege-tree)))

(defn- non-abstract-privileges []
  (set (keep (fn [[k v]] (when-not (:abstract v) k)) privilege-tree)))

(defn- direct-children [priv] (:children (get-privilege-info priv) #{}))

(defn- expand-privilege
  "Expand a privilege to include all its child privileges recursively."
  [priv]
  (loop [result #{} queue [priv]]
    (if (empty? queue)
      result
      (let [current (first queue)
            children (direct-children current)]
        (recur (conj result current) (into (rest queue) children))))))

(defn- expand-privileges
  "Expand a set of privileges to include all children."
  [privs]
  (into #{} (mapcat expand-privilege) privs))

(defn required-privileges-for-method
  "Return the set of privileges required to execute a method on a resource.
   `exists?` is whether the resource currently exists."
  [method exists?]
  (case (keyword (str/lower-case (name method)))
    (:get :head :options)          #{:dav/read}
    (:put :patch)                  (if exists? #{:dav/write-content} #{:dav/bind :dav/write-content})
    :delete                        #{:dav/unbind :dav/write-content}
    :mkcol                         #{:dav/bind :dav/write-content}
    :propfind                      #{:dav/read}
    :proppatch                     #{:dav/write-properties}
    :move                          #{:dav/unbind :dav/bind}
    :copy                          #{:dav/read :dav/bind :dav/write-content}
    :lock                          #{:dav/write}
    :unlock                        #{:dav/unlock}
    :acl                           #{:dav/write-acl}
    :report                        #{:dav/read}
    #{}))

(defn- principal-matches?
  "Check if the current authenticated user matches an ACE's principal spec.
   auth-user is a map with at least :principal-url.
   state is the application state atom value."
  [principal-spec auth-user resource-path state]
  (let [ptype (:type principal-spec)
        pval  (:value principal-spec)]
    (case ptype
      :all            true
      :authenticated  (some? auth-user)
      :unauthenticated (nil? auth-user)
      :self           (and (some? auth-user)
                           (= (:principal-url auth-user) resource-path))
      :href           (and (some? auth-user)
                           (let [u (:principal-url auth-user)]
                             (or (= u pval)
                                 (contains? (get-in state [:groups u] #{}) pval)
                                 (contains? (get-in state [:groups pval] #{}) u))))
      :property       (let [prop-key pval
                            owner-val (get-in state [:properties resource-path prop-key])]
                        (and (some? auth-user) owner-val
                             (= (:principal-url auth-user) owner-val)))
      :invert         (not (principal-matches? pval auth-user resource-path state))
      false)))

(defn evaluate-acl
  "Evaluate an ACL for a given request. Returns true if access is granted.

   Per RFC 3744 Section 6: ACEs are evaluated in order. A matching deny ACE
   for an ungranted required privilege causes immediate denial. Grant ACEs
   accumulate. When all required privileges are granted, access is allowed."
  [acl required-privs auth-user resource-path state]
  (let [required (expand-privileges required-privs)]
    (loop [aces acl
           granted #{}]
      (if (empty? aces)
        (empty? (set/difference required granted))
        (let [ace      (first aces)
              matches? (principal-matches? (:principal ace) auth-user resource-path state)]
          (if-not matches?
            (recur (rest aces) granted)
            (case (:type ace)
              :deny
              (let [denied (expand-privileges (:privileges ace))
                    still-needed (set/difference (set/intersection required denied) granted)]
                (if (seq still-needed) false (recur (rest aces) granted)))
              :grant
              (let [new-granted (set/union granted (expand-privileges (:privileges ace)))]
                (if (empty? (set/difference required new-granted))
                  true
                  (recur (rest aces) new-granted))))))))))

(defn current-user-privileges
  "Compute the set of non-abstract privileges the current user has on a resource."
  [resource-path auth-user state]
  (let [acl (get-in state [:acls resource-path])]
    (if (empty? acl)
      #{}
      (loop [aces acl granted #{}]
        (if (empty? aces)
          (set/intersection granted (non-abstract-privileges))
          (let [ace      (first aces)
                matches? (principal-matches? (:principal ace) auth-user resource-path state)]
            (if-not matches?
              (recur (rest aces) granted)
              (case (:type ace)
                :deny  (recur (rest aces) (set/difference granted (expand-privileges (:privileges ace))))
                :grant (recur (rest aces) (set/union granted (expand-privileges (:privileges ace))))))))))))

(defn default-acl
  "Create a default ACL for a new resource owned by owner-href."
  [owner-href]
  [{:type :grant :principal {:type :href :value owner-href} :privileges #{:dav/all}
    :protected? false :inherited nil}
   {:type :grant :principal {:type :authenticated :value nil} :privileges #{:dav/read}
    :protected? false :inherited nil}])

(defn home-acl
  "Create an ACL for a user's home directory. Only the user and admin have access."
  [owner-href admin-href]
  (cond-> [{:type :grant :principal {:type :href :value owner-href} :privileges #{:dav/all}
            :protected? false :inherited nil}]
    (and admin-href (not= admin-href owner-href))
    (conj {:type :grant :principal {:type :href :value admin-href} :privileges #{:dav/all}
           :protected? false :inherited nil})))

(def default-acl-restrictions
  {:grant-only? false :no-invert? false :deny-before-grant? false :required-principals []})

(defn method-requires-privileges?
  [method]
  (contains? #{:get :head :put :delete :mkcol :propfind :proppatch
               :move :copy :lock :unlock :acl :report :options :patch}
             (keyword (str/lower-case (name method)))))

(defn supported-privileges
  "Return the full privilege tree info as a seq of maps for XML generation."
  []
  (for [[priv info] privilege-tree]
    (assoc info :privilege priv)))

(defn validate-ace-privileges
  "Validate that an ACE's privileges are all non-abstract and known."
  [privs]
  (every? #(and (contains? (all-privileges) %)
                (not (abstract-privilege? %)))
          privs))
