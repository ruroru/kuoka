(ns jj.kuoka.handler
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [jj.kuoka.acl :as acl]
            [jj.kuoka.xml :as xml])
  (:import (clojure.lang ExceptionInfo)
           (java.io File)
           (java.net URI URLDecoder)
           (java.time Instant)
           (java.util Base64 UUID)))

(defn- decode-path [s] (when s (URLDecoder/decode ^String s "UTF-8")))

(defn- ensure-trailing-slash [s] (if (str/ends-with? s "/") s (str s "/")))

(defn- absolute-root [root] (.getAbsolutePath (io/file root)))

(defn- safe-path [root path]
  (let [decoded    (decode-path path)
        normalized (str/replace decoded #"\\" "/")
        cleaned    (str/replace normalized #"/{2,}" "/")
        ab-root    (absolute-root root)
        resolved   (str (ensure-trailing-slash ab-root)
                        (str/replace cleaned #"^/+" ""))]
    (if (.startsWith (.getCanonicalPath (io/file resolved))
                     (.getCanonicalPath (io/file ab-root)))
      resolved
      (throw (ex-info "Path traversal detected" {:path path})))))

(defn- file-exists? [root path] (try (.exists (io/file (safe-path root path))) (catch Exception _ false)))
(defn- is-directory? [root path] (try (.isDirectory (io/file (safe-path root path))) (catch Exception _ false)))
(defn- file-length   [root path] (try (.length (io/file (safe-path root path))) (catch Exception _ 0)))
(defn- last-modified [root path] (try (-> (io/file (safe-path root path)) .lastModified Instant/ofEpochMilli .toString) (catch Exception _ "")))

(defn- parent-path [path]
  (if (or (= path "/") (empty? path) (= path ""))
    "/"
    (let [p (str/replace path #"/+$" "")
          idx (str/last-index-of p "/")]
      (if (or (nil? idx) (zero? idx)) "/" (str (subs p 0 (inc idx)))))))

(defn- resource-url [request path]
  (str (name (:scheme request)) "://" (get-in request [:headers "host"]) path))

(defn- mime-type [^String path]
  (let [ext (-> path io/file .getName (str/lower-case) (str/split #"\.") last)]
    (case ext
      "html" "text/html" "htm" "text/html" "css" "text/css" "js" "application/javascript"
      "json" "application/json" "xml" "application/xml" "txt" "text/plain" "md" "text/markdown"
      "png" "image/png" "jpg" "image/jpeg" "jpeg" "image/jpeg" "gif" "image/gif"
      "svg" "image/svg+xml" "ico" "image/x-icon" "pdf" "application/pdf"
      "zip" "application/zip" "gz" "application/gzip" "tar" "application/x-tar"
      "mp3" "audio/mpeg" "mp4" "video/mp4" "webm" "video/webm"
      "woff" "font/woff" "woff2" "font/woff2" "ttf" "font/ttf"
      "csv" "text/csv" "yaml" "text/yaml" "yml" "text/yaml"
      "edn" "application/edn" "toml" "application/toml"
      "application/octet-stream")))

(defn- find-header [headers name]
  (loop [[k v] (first headers) more (rest headers)]
    (if (nil? k) nil
        (if (= (str/lower-case (str k)) (str/lower-case (str name)))
          v (recur (first more) (rest more))))))

(defn- get-header [request name]
  (let [headers (:headers request)]
    (or (get headers name) (get headers (str/lower-case name))
        (get headers (keyword (str/lower-case name))) (find-header headers name))))

(defn- extract-basic-auth [request]
  (when-let [auth-header (get-header request "authorization")]
    (when (str/starts-with? (str/lower-case auth-header) "basic ")
      (try (let [encoded (subs auth-header 6)
                 decoded (String. (.decode (Base64/getDecoder) encoded) "UTF-8")
                 [user pass] (str/split decoded #":" 2)]
             {:username user :password pass})
           (catch Exception _ nil)))))

(defn- authenticate [request]
  (if-let [creds (extract-basic-auth request)]
    (let [username (:username creds)
          password (:password creds)
          principals (:principals @(:state request))
          entry (first (filter (fn [[_ v]] (= (:username v) username)) principals))]
      (if (and entry (= password (:password (val entry))))
        {:username username :principal-url (key entry)}
        nil))
    nil))

(defn- auth-challenge []
  {:status 401 :headers {"Content-Type" "text/plain" "WWW-Authenticate" "Basic realm=\"WebDAV\""}
   :body "Authentication required"})

(defn- check-access! [request method path]
  (let [auth-user (:identity request)
        root (-> request :state deref :webdav-root)
        exists? (file-exists? root path)
        check-path (if exists? path (parent-path path))
        required-privs (acl/required-privileges-for-method method exists?)]
    (when (and (acl/method-requires-privileges? method) (seq required-privs))
      (let [st @(:state request)
            acls (get-in st [:acls check-path])
            allowed? (acl/evaluate-acl acls required-privs auth-user check-path st)]
        (when-not allowed?
          (throw (ex-info "Access denied" {:type :forbidden :required required-privs :resource check-path})))))))

(defn- compute-live-properties [path auth-user st root]
  (let [d @st exists? (file-exists? root path) is-dir? (is-directory? root path)]
    (merge (when exists?
             {:dav/resourcetype (when is-dir? :collection)
              :dav/getcontentlength (when-not is-dir? (file-length root path))
              :dav/getcontenttype (when-not is-dir? (mime-type path))
              :dav/getetag (when-not is-dir? (str (file-length root path) "-"
                                                  (.lastModified (io/file (safe-path root path)))))
              :dav/getlastmodified (last-modified root path)
              :dav/creationdate (last-modified root path)})
           {:dav/displayname (or (get-in d [:properties path :dav/displayname])
                                 (.getName (io/file ^String path)))
            :dav/supported-privilege-set (acl/supported-privileges)
            :dav/current-user-privilege-set (acl/current-user-privileges path auth-user d)
            :dav/acl (get-in d [:acls path])
            :dav/acl-restrictions acl/default-acl-restrictions
            :dav/inherited-acl-set (get-in d [:properties path :dav/inherited-acl-set] [])
            :dav/owner (get-in d [:properties path :dav/owner])
            :dav/group (get-in d [:properties path :dav/group])
            :dav/principal-collection-set (vec (keys (:principals d)))
            :dav/lockdiscovery (vals (get-in d [:locks path]))
            :dav/supportedlock true})))

(defn- properties-for [path auth-user requested st root]
  (let [live (compute-live-properties path auth-user st root)
        dead (get-in @st [:properties path] {})
        all  (merge dead live)]
    (cond (= requested :allprop)  all
          (= requested :propname) {:dav/propname (keys all)}
          :else                   (select-keys all requested))))

(defn- ensure-home-dir! [webdav-root username]
  (let [dir (io/file webdav-root username)]
    (when-not (.exists dir) (.mkdirs dir))))

(defn init-state
  "Return a fresh state atom with root ACL and webdav-root.
   Requires :admin-password to create the admin principal.
   Each user gets a home directory at /<username>/."
  [webdav-root & {:keys [admin-password]}]
  (let [st (atom {:webdav-root webdav-root
                  :properties {} :acls {} :locks {} :lock-tokens {}
                  :principals {} :groups {} :group-membership {}})]
    (when admin-password
      (ensure-home-dir! webdav-root "admin")
      (swap! st (fn [s]
                  (-> s
                      (assoc-in [:principals "/_principals/admin"]
                                {:displayname "Administrator" :username "admin"
                                 :password admin-password :principal-url "/_principals/admin"
                                 :resourcetype :principal})
                      (assoc-in [:acls "/"] (acl/default-acl "/_principals/admin"))
                      (assoc-in [:acls "/admin/"] (acl/home-acl "/_principals/admin" nil))))))
    st))

(defn add-user
  "Add a principal with password to the given state atom.
   Creates a home directory at /<username>/ with an isolated ACL.
   Returns the principal-url."
  [st username password & {:keys [displayname] :or {displayname username}}]
  (let [purl (str "/_principals/" username)
        home-path (str "/" username "/")
        webdav-root (:webdav-root @st)]
    (ensure-home-dir! webdav-root username)
    (swap! st (fn [s]
                (-> s
                    (assoc-in [:principals purl]
                              {:displayname displayname :username username :password password
                               :principal-url purl :resourcetype :principal})
                    (assoc-in [:acls home-path]
                              (acl/home-acl purl "/_principals/admin")))))
    purl))

(defn- current-root [request] (-> request :state deref :webdav-root))

(defn- inherit-or-default-acl [st path creator-url]
  (let [parent (parent-path path)
        parent-acl (get-in @st [:acls parent])]
    (or parent-acl (acl/default-acl creator-url))))

(defn- xml-response [body & [status]]
  {:status (or status 207) :headers {"Content-Type" "application/xml; charset=utf-8" "DAV" "1, 2, access-control"} :body body})

(defn- propfind-response [request path depth]
  (let [auth-user (:identity request)
        st (:state request)
        root (current-root request)
        requested (xml/parse-propfind (xml/parse-xml-body request))
        depth-val (str/lower-case (or depth "0"))
        collect (case depth-val
                  "0" [path]
                  "1" (if (is-directory? root path)
                        (let [dir (io/file (safe-path root path))
                              base (ensure-trailing-slash path)]
                          (cons path (for [^File f (.listFiles dir)
                                           :let [rel (str base (.getName f))]]
                                       rel)))
                        [path])
                  [path])
        responses (for [p collect :when (file-exists? root p)]
                    [p (->> (properties-for p auth-user requested st root)
                            (map (fn [[k v]] (xml/property-xml k v))))])]
    (xml-response (xml/multi-status-body responses))))

(defn- handle-options [path root]
  (let [allow (if (is-directory? root path)
                "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, PROPPATCH, MOVE, COPY, LOCK, UNLOCK, ACL, REPORT"
                "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MOVE, COPY, LOCK, UNLOCK, ACL, REPORT")]
    {:status 200 :headers {"Content-Type" "text/plain" "DAV" "1, 2, access-control" "Allow" allow} :body ""}))

(defn- handle-get [request path]
  (let [root (current-root request)]
    (check-access! request :get path)
    (if-not (file-exists? root path)
      {:status 404 :headers {} :body "Not Found"}
      (if (is-directory? root path)
        (let [dir (io/file (safe-path root path))
              files (sort (.list dir))
              html (str "<html><head><title>" (str/replace path #"/$" "") "</title></head><body>"
                        "<h1>" (str/replace path #"/$" "") "</h1><ul>"
                        (when-not (= "/" path) "<li><a href=\"..\">..</a></li>")
                        (str/join (for [^File f files]
                                    (str "<li><a href=\"" f (when (.isDirectory (io/file dir f)) "/")
                                         "\">" f (when (.isDirectory (io/file dir f)) "/") "</a></li>")))
                        "</ul></body></html>")]
          {:status 200 :headers {"Content-Type" "text/html; charset=utf-8"} :body html})
        {:status 200
         :headers {"Content-Type" (str (mime-type path) "; charset=utf-8")
                   "Content-Length" (str (file-length root path))
                   "ETag" (str "\"" (file-length root path) "-" (.lastModified (io/file (safe-path root path))) "\"")}
         :body (io/file (safe-path root path))}))))

(defn- handle-head [request path]
  (let [resp (handle-get request path)]
    (-> resp (assoc :body nil) (update :headers #(apply dissoc % ["Content-Length" "content-length"])))))

(defn- handle-put [request path]
  (let [root (current-root request)
        st (:state request)
        file (io/file (safe-path root path))
        dir  (.getParentFile file)
        body (:body request)]
    (check-access! request :put path)
    (when (and (not (.exists dir)) (not= dir nil)) (.mkdirs dir))
    (with-open [out (io/output-stream file)] (io/copy body out))
    (when-not (get-in @st [:acls path])
      (swap! st assoc-in [:acls path] (inherit-or-default-acl st path (some-> (:identity request) :principal-url))))
    (swap! st assoc-in [:properties path :dav/creationdate] (last-modified root path))
    (let [etag (str "\"" (file-length root path) "-" (.lastModified (io/file (safe-path root path))) "\"")]
      {:status 201 :headers {"ETag" etag "Location" (resource-url request path)} :body ""})))

(defn- handle-delete [request path]
  (let [root (current-root request)
        st (:state request)
        file (io/file (safe-path root path))]
    (check-access! request :delete path)
    (if (.exists file)
      (do (if (.isDirectory file)
            (doseq [^File f (reverse (file-seq file))] (.delete f))
            (.delete ^File file))
          (swap! st update :properties dissoc path)
          (swap! st update :acls dissoc path)
          (swap! st update :locks dissoc path)
          {:status 204 :headers {} :body nil})
      {:status 404 :headers {} :body "Not Found"})))

(defn- handle-mkcol [request path]
  (let [root (current-root request)
        st (:state request)
        file (io/file (safe-path root path))]
    (check-access! request :mkcol path)
    (if (.exists file)
      {:status 405 :headers {} :body "Method Not Allowed"}
      (do (.mkdirs file)
          (swap! st assoc-in [:acls path] (inherit-or-default-acl st path (some-> (:identity request) :principal-url)))
          (swap! st assoc-in [:properties path :dav/creationdate] (last-modified root path))
          {:status 201 :headers {} :body ""}))))

(defn- handle-propfind [request path]
  (let [root (current-root request)]
    (check-access! request :propfind path)
    (if-not (file-exists? root path)
      {:status 404 :headers {} :body "Not Found"}
      (let [depth (get-in request [:headers "depth"] "0")]
        (propfind-response request path depth)))))

(defn- handle-proppatch [request path]
  (let [root (current-root request)]
    (check-access! request :proppatch path)
    (if-not (file-exists? root path)
      {:status 404 :headers {} :body "Not Found"}
      (let [st (:state request)
            parsed (xml/parse-proppatch (xml/parse-xml-body request))
            to-set (:set parsed)
            to-remove (:remove parsed)
            protected #{:dav/acl :dav/acl-restrictions :dav/current-user-privilege-set
                        :dav/supported-privilege-set :dav/inherited-acl-set
                        :dav/principal-collection-set :dav/lockdiscovery :dav/supportedlock
                        :dav/resourcetype :dav/getcontentlength :dav/getcontenttype
                        :dav/getetag :dav/getlastmodified :dav/creationdate}
            failed (filter protected (set (concat (keys to-set) to-remove)))]
        (doseq [[k v] to-set :when (not (contains? protected k))]
          (swap! st assoc-in [:properties path k] v))
        (doseq [k to-remove :when (not (contains? protected k))]
          (swap! st update-in [:properties path] dissoc k))
        (if (seq failed)
          (xml-response (xml/multi-status-body
                          [[path [(xml/child-element "prop" {} (for [k failed] (xml/text-el (name k) "")))
                                  (xml/status-el "HTTP/1.1 403 Forbidden")
                                  (xml/child-element "responsedescription" {}
                                                     (xml/child-element "error" {} (xml/child-element "cannot-modify-protected-property" {})))]]])
                        207)
          (xml-response (xml/multi-status-body [[path [(xml/status-el "HTTP/1.1 200 OK")]]]) 207))))))

(defn- handle-move [request path]
  (let [root (current-root request)
        st (:state request)
        dest (some-> (get-header request "destination") decode-path
                     (#(try (.getPath (URI. ^String %)) (catch Exception _ nil))))
        src-file (io/file (safe-path root path))
        dst-file (when dest (io/file (safe-path root dest)))]
    (check-access! request :move path)
    (if (or (not dest) (not (.exists src-file)))
      {:status 404 :headers {} :body "Not Found"}
      (do (.mkdirs (.getParentFile dst-file))
          (io/copy src-file dst-file)
          (let [props (get-in @st [:properties path])
                acls  (get-in @st [:acls path])
                locks (get-in @st [:locks path])]
            (swap! st update :properties #(-> % (dissoc path) (assoc dest props)))
            (swap! st update :acls  #(-> % (dissoc path) (assoc dest acls)))
            (swap! st update :locks #(-> % (dissoc path) (assoc dest locks))))
          (.delete src-file)
          {:status 201 :headers {} :body ""}))))

(defn- handle-copy [request path]
  (let [root (current-root request)
        st (:state request)
        dest (some-> (get-header request "destination") decode-path
                     (#(try (.getPath (URI. ^String %)) (catch Exception _ nil))))
        src-file (io/file (safe-path root path))
        dst-file (when dest (io/file (safe-path root dest)))]
    (check-access! request :copy path)
    (if (or (not dest) (not (.exists src-file)))
      {:status 404 :headers {} :body "Not Found"}
      (do (.mkdirs (.getParentFile dst-file))
          (if (.isDirectory src-file)
            (doseq [^File f (file-seq src-file) :when (.isFile f)]
              (let [rel (str/replace-first (.getPath f) (str/replace (.getPath ^File src-file) "\\" "/") "")]
                (io/copy f (io/file (str (.getPath ^File dst-file) rel)))))
            (io/copy src-file dst-file))
          (swap! st assoc-in [:acls dest] (inherit-or-default-acl st dest (some-> (:identity request) :principal-url)))
          {:status 201 :headers {} :body ""}))))

(defn- handle-lock [request path]
  (let [root (current-root request)]
    (check-access! request :lock path)
    (if-not (file-exists? root path)
      {:status 404 :headers {} :body "Not Found"}
      (let [st (:state request)
            token (str "opaquelocktoken:" (UUID/randomUUID))
            lock {:token token :owner (some-> (:identity request) :principal-url)
                  :scope :exclusive
                  :depth (or (get-in request [:headers "depth"]) "infinity")
                  :timeout (or (get-in request [:headers "timeout"]) "Second-3600")
                  :path path}]
        (swap! st update-in [:locks path] (fnil conj []) lock)
        (swap! st assoc-in [:lock-tokens token] lock)
        {:status 200
         :headers {"Content-Type" "application/xml; charset=utf-8" "Lock-Token" (str "<" token ">")}
         :body (xml/emit-xml (xml/element "prop" {} (xml/child-element "lockdiscovery" {} (xml/lock-entry-xml lock))))}))))

(defn- handle-unlock [request path]
  (check-access! request :unlock path)
  (let [st (:state request)
        lock-token (get-in request [:headers "lock-token"])]
    (if-let [token (when lock-token (second (re-find #"<([^>]+)>" lock-token)))]
      (if-let [lock (get-in @st [:lock-tokens token])]
        (do (swap! st update-in [:locks (:path lock)] (fn [locks] (vec (remove #(= (:token %) token) locks))))
            (swap! st update :lock-tokens dissoc token)
            {:status 204 :headers {} :body nil})
        {:status 409 :headers {} :body "Conflict"})
      {:status 400 :headers {} :body "Bad Request"})))

(defn- handle-acl [request path]
  (let [root (current-root request)]
    (check-access! request :acl path)
    (if-not (file-exists? root path)
      {:status 404 :headers {} :body "Not Found"}
      (let [st (:state request)
            locks (get-in @st [:locks path])
            auth-user (:identity request)]
        (when (and (seq locks) (not (some #(= (:owner %) (:principal-url auth-user)) locks)))
          (throw (ex-info "Resource is locked" {:type :locked :status 423})))
        (let [parsed (xml/parse-acl-body (xml/parse-xml-body request))
              valid? (every? #(acl/validate-ace-privileges (:privileges %)) parsed)]
          (if-not valid?
            {:status 400 :headers {} :body "Invalid privileges in ACL"}
            (do (swap! st assoc-in [:acls path]
                       (let [inherited (keep #(when (:inherited %) %) (get-in @st [:acls path]))]
                         (concat inherited parsed)))
                {:status 200 :headers {} :body ""})))))))

(defn- handle-report [request path]
  (check-access! request :report path)
  (let [st (:state request)
        parsed (xml/parse-report-body (xml/parse-xml-body request))
        auth-user (:identity request)]
    (case (:type parsed)
      :principal-property-search
      (let [search-spec (:search-spec parsed)
            prop-names (:prop parsed)
            principals (:principals @st)
            match-val (some-> (get search-spec :dav/match) str/lower-case)
            search-prop (or (:dav/prop search-spec) :dav/displayname)
            matches (filter (fn [[_ pdata]]
                              (when-let [val (get pdata search-prop)]
                                (str/includes? (str/lower-case (str val)) match-val)))
                            principals)]
        (xml-response (xml/multi-status-body
                        (for [[purl pdata] matches]
                          [purl (->> (select-keys pdata prop-names)
                                     (map (fn [[k v]] (xml/property-xml k v))))]))))

      :principal-search-property-set
      (xml-response (xml/multi-status-body
                      [[path [(xml/child-element "principal-search-property-set" {}
                                                 (xml/child-element "principal-search-property" {}
                                                                    (xml/child-element "prop" {} (xml/child-element "displayname" {}))
                                                                    (xml/child-element "description" {(keyword "xml:lang") "en"} "Display name")))]]]))

      :acl-principal-prop-set
      (let [prop-names (:prop parsed)
            principals (:principals @st)]
        (xml-response (xml/multi-status-body
                        (for [[purl pdata] principals]
                          [purl (->> (select-keys pdata prop-names)
                                     (map (fn [[k v]] (xml/property-xml k v))))]))))

      :principal-match
      (let [principals (:principals @st)
            matches (filter (fn [[_ pdata]] (= (:principal-url pdata) (:principal-url auth-user))) principals)]
        (xml-response (xml/multi-status-body
                        (for [[purl pdata] matches]
                          [purl (map (fn [[k v]] (xml/property-xml k v)) pdata)]))))

      {:status 400 :headers {} :body "Unknown report type"})))

(defn- wrap-state [handler state-atom]
  (fn [request] (handler (assoc request :state state-atom))))

(defn- wrap-auth [handler]
  (fn [request]
    (let [auth-user (authenticate request)]
      (if auth-user
        (handler (assoc request :identity auth-user))
        (if (= :options (keyword (name (:request-method request))))
          (handler (assoc request :identity {:username "anonymous" :principal-url nil}))
          (auth-challenge))))))

(defn- wrap-user-scope [handler]
  (fn [request]
    (let [username (get-in request [:identity :username])
          scope (fn [p] (str "/" username (if (str/starts-with? p "/") p (str "/" p))))
          scoped-request (update request :uri #(scope (or % "/")))
          dest (get-header request "destination")]
      (if dest
        (try
          (let [u (URI. ^String dest)
                scoped-dest (str (URI. (.getScheme u) (.getAuthority u) (scope (.getPath u)) nil nil))]
            (handler (assoc-in scoped-request [:headers "destination"] scoped-dest)))
          (catch Exception _ (handler scoped-request)))
        (handler scoped-request)))))

(defn- wrap-error [handler]
  (fn [request]
    (try (handler request)
         (catch ExceptionInfo e
           (let [data (ex-data e)]
             (case (:type data)
               :forbidden {:status 403 :headers {"Content-Type" "application/xml; charset=utf-8"}
                           :body (xml/error-body [[(:resource data) (first (:required data))]])}
               {:status 500 :headers {"Content-Type" "text/plain"}
                :body "Internal Server Error"})))
         (catch Exception e
           {:status 500 :headers {"Content-Type" "text/plain"}
            :body "Internal Server Error"}))))

(defn- wrap-dav-headers [handler]
  (fn [request]
    (let [response (handler request)]
      (if (contains? #{200 201 204 207 401 403 404 405 409} (:status response))
        (update response :headers #(merge {"DAV" "1, 2, access-control"} %))
        response))))

(defn- handler [request]
  (let [root (current-root request)
        request (-> request (update :uri #(or % "/")) (update :request-method #(or % :get)))
        method  (keyword (name (:request-method request)))
        path    (:uri request)]
    (when (str/includes? path "..")
      (throw (ex-info "Invalid path" {:type :forbidden :required #{:dav/read} :resource path})))
    (case method
      :options   (handle-options path root)
      :get       (handle-get request path)
      :head      (handle-head request path)
      :put       (handle-put request path)
      :delete    (handle-delete request path)
      :mkcol     (handle-mkcol request path)
      :propfind  (handle-propfind request path)
      :proppatch (handle-proppatch request path)
      :move      (handle-move request path)
      :copy      (handle-copy request path)
      :lock      (handle-lock request path)
      :unlock    (handle-unlock request path)
      :acl       (handle-acl request path)
      :report    (handle-report request path)
      {:status 405
       :headers {"Allow" "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, PROPPATCH, MOVE, COPY, LOCK, UNLOCK, ACL, REPORT"}
       :body "Method Not Allowed"})))

(defn make-app
  "Create the full Ring handler stack, injecting the given state atom.
   The state atom must contain :webdav-root (set by init-state)."
  [state]
  (wrap-state (-> handler wrap-error wrap-user-scope wrap-auth wrap-dav-headers) state))
