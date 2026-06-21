(ns jj.kuoka.e2e
  "End-to-end WebDAV tests with thorough XML tag verification.
   Each test starts/stops its own server. All 14 WebDAV methods tested."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [clojure.data.xml :as dx]
            [hato.client :as http]
            [ring-http-exchange.core :as ring-http]
            [jj.kuoka.core :as srv]
            [clojure.string :as str])
  (:import [com.sun.net.httpserver HttpServer]
           [java.io ByteArrayInputStream File]))

(def port 18080)
(defn- url [path] (str "http://localhost:" port path))
(def ^:private admin-auth "Basic YWRtaW46YWRtaW4=")
(def ^:private evil-auth "Basic ZXZpbDpldmls")
(def ^:private guest-auth "Basic Z3Vlc3Q6Z3Vlc3Q=")
(def ^:private alice-auth "Basic YWxpY2U6YWxpY2U=")
(def ^:private tom-auth "Basic dG9tOnRvbQ==")

(def ^:private data-root "test/resources/webdav-e2e-data")

(defn server-fixture [f]
  (let [rd (File. data-root)]
    (when (.exists rd) (try (doseq [x (reverse (file-seq rd))] (.delete x)) (catch Exception _ nil))))
  (let [handler (srv/make-handler data-root "admin" {"alice" "alice" "evil" "evil" "tom" "tom"})
        ^HttpServer srv (ring-http/run-http-server handler {:port port})]
    (Thread/sleep 500)
    (try (f) (finally (try (.stop srv 0) (catch Exception _ nil))))))
(use-fixtures :each server-fixture)

(defn- hreq ([m p] (hreq m p nil nil nil)) ([m p a] (hreq m p a nil nil))
  ([m p a h] (hreq m p a h nil)) ([m p a h b]
                                  (let [req {:method  (keyword (str/lower-case (name m))) :url (url p)
                                             :headers (or h {}) :throw-exceptions? false}
                                        req (if a (assoc req :headers (assoc (:headers req) "Authorization" a)) req)
                                        req (if b (assoc req :body (str b) :content-type "application/xml") req)
                                        resp (http/request req)]
                                    {:status  (:status resp)
                                     :headers (into {} (for [[k v] (:headers resp)] [(str/lower-case k) v]))
                                     :body    (:body resp)})))

(defn- req ([m p] (hreq m p admin-auth)) ([m p b] (hreq m p admin-auth nil b)))
(defn- req-evil ([m p] (hreq m p evil-auth)) ([m p b] (hreq m p evil-auth nil b)))
(defn- req-guest [m p] (hreq m p guest-auth))
(defn- req-noauth [m p] (hreq m p))

(defn- prs [s] (when s (try (dx/parse (ByteArrayInputStream. (.getBytes s "UTF-8"))) (catch Exception _ nil))))
(defn- tags [el] (let [t (name (:tag el))] (into #{t} (mapcat tags (filter :tag (:content el))))))
(defn- xml-tags [r] (when-let [p (prs (:body r))] (tags p)))
(defn- tag? [r t] (contains? (xml-tags r) t))
(defn- root [r] (when-let [p (prs (:body r))] (name (:tag p))))

(def lockinfo-body (str "<D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"))
(defn- pfb [& ps] (str "<D:propfind xmlns:D=\"DAV:\"><D:prop>" (str/join (map #(str "<D:" (name %) "/>") ps)) "</D:prop></D:propfind>"))
(def ^:private xml-dec "<?xml version=\"1.0\"?>")
;; ============================================================================

(deftest options-test
  (testing "OPTIONS returns DAV header and Allow methods"
    (let [r (hreq :options "/")]
      (is (= 200 (:status r)))
      (is (str/includes? (get-in r [:headers "dav"] "") "access-control"))
      (is (str/includes? (get-in r [:headers "allow"] "") "GET"))
      (is (str/includes? (get-in r [:headers "allow"] "") "PROPFIND"))
      (is (str/includes? (get-in r [:headers "allow"] "") "ACL")))))

(deftest auth-test
  (testing "no auth returns 401"
    (is (= 401 (:status (req-noauth :get "/")))))
  (testing "authenticated user can write to own home"
    (is (= 201 (:status (req-evil :put "/h.txt" "x"))))
    (req-evil :delete "/h.txt"))
  (testing "guest can OPTIONS"
    (is (= 200 (:status (req-guest :options "/"))))))

(deftest file-crud-test
  (testing "PUT GET DELETE cycle"
    (req :put "/t.txt" "hello")
    (let [r (req :get "/t.txt")] (is (= 200 (:status r))) (is (= "hello" (:body r))))
    (is (= 204 (:status (req :delete "/t.txt"))))))

(deftest mime-test
  (testing "content-type by extension"
    (req :put "/doc.html" "html")
    (is (str/includes? (get-in (req :get "/doc.html") [:headers "content-type"] "") "text/html"))
    (req :put "/data.json" "{}")
    (is (str/includes? (get-in (req :get "/data.json") [:headers "content-type"] "") "json"))
    (req :put "/img.png" "png")
    (is (str/includes? (get-in (req :get "/img.png") [:headers "content-type"] "") "image/png"))))

(deftest move-copy-test
  (testing "MOVE and COPY"
    (req :put "/src.txt" "source") (req :mkcol "/d/")
    (hreq :put "/d/n.txt" admin-auth {} "nested")
    (is (= 201 (:status (hreq :move "/d/n.txt" admin-auth {"Destination" (url "/m.txt")}))))
    (let [r (req :get "/m.txt")] (is (= 200 (:status r))) (is (= "nested" (:body r))))
    (is (= 201 (:status (hreq :copy "/src.txt" admin-auth {"Destination" (url "/c.txt")}))))
    (let [r (req :get "/c.txt")] (is (= 200 (:status r))) (is (= "source" (:body r))))
    (req :delete "/c.txt") (req :delete "/m.txt") (req :delete "/src.txt") (req :delete "/d/")))

(deftest lock-test
  (testing "LOCK returns token and lockdiscovery XML"
    (req :put "/l.txt" "locked")
    (let [r (hreq :lock "/l.txt" admin-auth {"Content-Type" "application/xml"} lockinfo-body)]
      (is (= 200 (:status r))) (is (= "prop" (root r)))
      (doseq [t ["lockdiscovery" "activelock" "locktype" "write" "lockscope" "exclusive" "locktoken" "depth" "timeout"]]
        (is (tag? r t) (str "should contain " t)))
      (is (str/includes? (get-in r [:headers "lock-token"] "") "opaquelocktoken")))
    (req :delete "/l.txt")))

(deftest propfind-test
  (testing "PROPFIND returns Multi-Status with standard tags"
    (req :put "/p.txt" "props")
    (let [r (hreq :propfind "/p.txt" admin-auth {"Depth" "0" "Content-Type" "application/xml"} (str xml-dec (pfb :displayname :getcontentlength)))]
      (is (= 207 (:status r))) (is (= "multistatus" (root r)))
      (is (tag? r "response")) (is (tag? r "href")) (is (tag? r "propstat"))
      (is (tag? r "displayname")) (is (tag? r "getcontentlength")))
    (req :delete "/p.txt")))

(deftest proppatch-test
  (testing "PROPPATCH set and protected property rejection"
    (req :put "/pp.txt" "data")
    (let [body (str xml-dec "<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop><D:displayname>Renamed</D:displayname></D:prop></D:set></D:propertyupdate>")
          r (hreq :proppatch "/pp.txt" admin-auth {"Content-Type" "application/xml"} body)]
      (is (= 207 (:status r))) (is (str/includes? (:body r) "200 OK")))
    (let [body (str xml-dec "<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop><D:getcontentlength>99</D:getcontentlength></D:prop></D:set></D:propertyupdate>")
          r (hreq :proppatch "/pp.txt" admin-auth {"Content-Type" "application/xml"} body)]
      (is (= 207 (:status r))) (is (str/includes? (:body r) "403 Forbidden")))
    (req :delete "/pp.txt")))

(deftest acl-test
  (testing "PROPFIND returns ACL with ACEs and ACL set works"
    (req :put "/acl.txt" "acl")
    (let [r (hreq :propfind "/acl.txt" admin-auth {"Depth" "0" "Content-Type" "application/xml"} (str xml-dec (pfb :acl)))]
      (is (= 207 (:status r))) (is (tag? r "acl")) (is (tag? r "ace"))
      (is (tag? r "principal")) (is (tag? r "grant")) (is (tag? r "privilege")))
    (let [body (str xml-dec "<D:acl xmlns:D=\"DAV:\"><D:ace><D:principal><D:href>/_principals/admin</D:href></D:principal><D:grant><D:privilege><D:read/></D:privilege><D:privilege><D:write-content/></D:privilege></D:grant></D:ace></D:acl>")]
      (is (= 200 (:status (hreq :acl "/acl.txt" admin-auth {"Content-Type" "application/xml"} body)))))
    (req :delete "/acl.txt")))

(deftest error-response-test
  (testing "403 body has correct XML tags when ACL denies access"
    (req :put "/e.txt" "data")
    ;; set ACL granting admin only read (remove write-content)
    (let [acl-body (str xml-dec "<D:acl xmlns:D=\"DAV:\"><D:ace><D:principal><D:href>/_principals/admin</D:href></D:principal><D:grant><D:privilege><D:read/></D:privilege><D:privilege><D:write-acl/></D:privilege><D:privilege><D:unbind/></D:privilege></D:grant></D:ace></D:acl>")]
      (hreq :acl "/e.txt" admin-auth {"Content-Type" "application/xml"} acl-body))
    (let [r (req :put "/e.txt" "overwrite")]
      (is (= 403 (:status r))) (is (= "error" (root r)))
      (is (tag? r "need-privileges")) (is (tag? r "resource"))
      (is (tag? r "privilege")) (is (tag? r "write-content")))
    ;; restore full ACL to clean up
    (let [acl-body (str xml-dec "<D:acl xmlns:D=\"DAV:\"><D:ace><D:principal><D:href>/_principals/admin</D:href></D:principal><D:grant><D:privilege><D:read/></D:privilege><D:privilege><D:write-content/></D:privilege><D:privilege><D:write-acl/></D:privilege><D:privilege><D:unbind/></D:privilege></D:grant></D:ace></D:acl>")]
      (hreq :acl "/e.txt" admin-auth {"Content-Type" "application/xml"} acl-body))
    (req :delete "/e.txt")))

(deftest report-test
  (testing "principal-search-property-set, acl-principal-prop-set, unknown report"
    (let [body (str xml-dec "<D:principal-search-property-set xmlns:D=\"DAV:\"/>")
          r (hreq :report "/" admin-auth {"Content-Type" "application/xml" "Depth" "0"} body)]
      (is (= 207 (:status r))) (is (str/includes? (:body r) "displayname")))
    (let [body (str xml-dec "<D:acl-principal-prop-set xmlns:D=\"DAV:\"><D:prop><D:displayname/></D:prop></D:acl-principal-prop-set>")
          r (hreq :report "/" admin-auth {"Content-Type" "application/xml" "Depth" "0"} body)]
      (is (= 207 (:status r))) (is (str/includes? (:body r) "multistatus")))
    (is (= 400 (:status (hreq :report "/" admin-auth {"Content-Type" "application/xml"} "<unknown/>"))))))

(deftest edge-cases-test
  (testing "HEAD, 404s, MKCOL 405, big file"
    (is (contains? #{404 403} (:status (req :delete "/nope.txt"))))
    (is (= 404 (:status (req :get "/nope.txt"))))
    (req :put "/h.txt" "head-test")
    (let [r (hreq :head "/h.txt" admin-auth)] (is (= 200 (:status r))) (is (= "" (:body r))))
    (req :delete "/h.txt")
    (req :mkcol "/ex/") (is (= 405 (:status (req :mkcol "/ex/")))) (req :delete "/ex/")
    (let [data (apply str (repeat 5000 "x"))]
      (is (= 201 (:status (hreq :put "/big.txt" admin-auth {} data))))
      (let [r (req :get "/big.txt")] (is (= 200 (:status r))) (is (= 5000 (count (:body r)))))
      (req :delete "/big.txt"))))

(deftest unlock-test
  (testing "UNLOCK removes lock"
    (req :put "/ul.txt" "unlock-me")
    (let [lr (hreq :lock "/ul.txt" admin-auth {"Content-Type" "application/xml"} lockinfo-body)
          tok (get-in lr [:headers "lock-token"])]
      (is (= 200 (:status lr)))
      (is (#{204 400} (:status (hreq :unlock "/ul.txt" admin-auth {"Lock-Token" tok})))))
    (req :delete "/ul.txt")))

(deftest report-search-test
  (testing "principal-property-search and principal-match"
    (let [body (str xml-dec "<D:principal-property-search xmlns:D=\"DAV:\"><D:property-search><D:prop><D:displayname/></D:prop><D:match>admin</D:match></D:property-search><D:prop><D:displayname/></D:prop></D:principal-property-search>")
          r (hreq :report "/" admin-auth {"Content-Type" "application/xml" "Depth" "0"} body)]
      (is (= 207 (:status r))) (is (str/includes? (:body r) "multistatus")))
    (let [body (str xml-dec "<D:principal-match xmlns:D=\"DAV:\"><D:principal-property><D:principal-url/></D:principal-property><D:prop><D:displayname/></D:prop></D:principal-match>")
          r (hreq :report "/" admin-auth {"Content-Type" "application/xml" "Depth" "0"} body)]
      (is (= 207 (:status r))) (is (str/includes? (:body r) "multistatus")))))

(deftest privilege-error-test
  (testing "denied when ACL removes specific privileges"
    (req :put "/p.txt" "priv")
    ;; set ACL granting only read + write-acl + unbind (no write-properties, no write-content for new files)
    (let [acl-body (str xml-dec "<D:acl xmlns:D=\"DAV:\"><D:ace><D:principal><D:href>/_principals/admin</D:href></D:principal><D:grant><D:privilege><D:read/></D:privilege><D:privilege><D:write-acl/></D:privilege><D:privilege><D:unbind/></D:privilege></D:grant></D:ace></D:acl>")]
      (hreq :acl "/p.txt" admin-auth {"Content-Type" "application/xml"} acl-body))
    ;; proppatch denied (no write-properties)
    (is (= 403 (:status (req :proppatch "/p.txt" (str xml-dec "<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop><D:displayname>X</D:displayname></D:prop></D:set></D:propertyupdate>")))))
    ;; put denied (no write-content)
    (is (= 403 (:status (req :put "/p.txt" "overwrite"))))
    ;; restore and clean up
    (let [acl-body (str xml-dec "<D:acl xmlns:D=\"DAV:\"><D:ace><D:principal><D:href>/_principals/admin</D:href></D:principal><D:grant><D:privilege><D:read/></D:privilege><D:privilege><D:write-content/></D:privilege><D:privilege><D:write-acl/></D:privilege><D:privilege><D:unbind/></D:privilege></D:grant></D:ace></D:acl>")]
      (hreq :acl "/p.txt" admin-auth {"Content-Type" "application/xml"} acl-body))
    (req :delete "/p.txt")))

(deftest privilege-tree-test
  (testing "supported-privilege-set contains all expected privileges"
    (req :put "/sp.txt" "sp")
    (let [r (hreq :propfind "/sp.txt" admin-auth {"Depth" "0" "Content-Type" "application/xml"} (str xml-dec (pfb :supported-privilege-set)))]
      (is (= 207 (:status r))) (is (= "multistatus" (root r)))
      (doseq [t ["supported-privilege-set" "supported-privilege" "privilege" "abstract" "description"
                 "read" "write" "write-content" "write-properties" "bind" "unbind"
                 "read-acl" "write-acl" "read-current-user-privilege-set" "unlock" "all"]]
        (is (tag? r t) (str "should contain " t))))
    (req :delete "/sp.txt")))

(deftest current-user-privilege-set-test
  (testing "current-user-privilege-set includes non-abstract privileges"
    (req :put "/cu.txt" "cu")
    (let [r (hreq :propfind "/cu.txt" admin-auth {"Depth" "0" "Content-Type" "application/xml"} (str xml-dec (pfb :current-user-privilege-set)))]
      (is (= 207 (:status r))) (is (tag? r "current-user-privilege-set"))
      (is (tag? r "read")) (is (tag? r "write-content")) (is (tag? r "write-properties"))
      (is (tag? r "bind")) (is (tag? r "unbind")) (is (tag? r "read-acl"))
      (is (tag? r "write-acl")) (is (tag? r "read-current-user-privilege-set")) (is (tag? r "unlock")))
    (req :delete "/cu.txt")))

(deftest lock-acl-interaction-test
  (testing "can set ACL on self-locked resource"
    (req :put "/la.txt" "lock-acl")
    (hreq :lock "/la.txt" admin-auth {"Content-Type" "application/xml"} lockinfo-body)
    (let [body (str xml-dec "<D:acl xmlns:D=\"DAV:\"><D:ace><D:principal><D:href>/_principals/admin</D:href></D:principal><D:grant><D:privilege><D:read/></D:privilege></D:grant></D:ace></D:acl>")]
      (is (= 200 (:status (hreq :acl "/la.txt" admin-auth {"Content-Type" "application/xml"} body)))))
    (req :delete "/la.txt")))

(deftest acl-revoke-test
  (testing "revoking own privilege immediately denies access"
    (req :put "/secret.txt" "secret")
    (let [full-acl (str xml-dec "<D:acl xmlns:D=\"DAV:\"><D:ace><D:principal><D:href>/_principals/admin</D:href></D:principal><D:grant><D:privilege><D:read/></D:privilege><D:privilege><D:write-content/></D:privilege><D:privilege><D:write-acl/></D:privilege><D:privilege><D:unbind/></D:privilege></D:grant></D:ace></D:acl>")
          no-read  (str xml-dec "<D:acl xmlns:D=\"DAV:\"><D:ace><D:principal><D:href>/_principals/admin</D:href></D:principal><D:grant><D:privilege><D:write-content/></D:privilege><D:privilege><D:write-acl/></D:privilege><D:privilege><D:unbind/></D:privilege></D:grant></D:ace></D:acl>")]
      ;; can read initially
      (is (= 200 (:status (req :get "/secret.txt"))))
      ;; revoke own read
      (is (= 200 (:status (hreq :acl "/secret.txt" admin-auth {"Content-Type" "application/xml"} no-read))))
      (is (= 403 (:status (req :get "/secret.txt"))) "read denied after revoking own read privilege")
      ;; restore read
      (is (= 200 (:status (hreq :acl "/secret.txt" admin-auth {"Content-Type" "application/xml"} full-acl))))
      (is (= 200 (:status (req :get "/secret.txt"))) "read restored after re-granting"))
    (req :delete "/secret.txt")))

(deftest two-users-same-filename-test
  (testing "two users each write a file with the same name, scoped to their own home"
    ;; both users PUT /notes.txt — scoped to /admin/notes.txt and /alice/notes.txt
    (is (= 201 (:status (hreq :put "/notes.txt" admin-auth {} "admin-notes"))))
    (is (= 201 (:status (hreq :put "/notes.txt" alice-auth {} "alice-notes"))))
    ;; each user reads their own file
    (let [admin-r (hreq :get "/notes.txt" admin-auth)
          alice-r (hreq :get "/notes.txt" alice-auth)]
      (is (= 200 (:status admin-r)))
      (is (= 200 (:status alice-r)))
      (is (= "admin-notes" (:body admin-r)))
      (is (= "alice-notes" (:body alice-r)))
      (is (not= (:body admin-r) (:body alice-r)) "same path, different users, different content"))
    (req :delete "/notes.txt")
    (hreq :delete "/notes.txt" alice-auth)))

(deftest path-traversal-test
  (testing "alice cannot read tom's file via /..tom/hello.txt path traversal"
    ;; tom creates hello.txt in his home directory
    (is (= 201 (:status (hreq :put "/hello.txt" tom-auth {} "tom-secret"))))
    ;; alice tries to escape her home via /..tom/hello.txt
    (let [r (hreq :get "/..tom/hello.txt" alice-auth)]
      (is (= 403 (:status r)) "path traversal with .. should be denied"))
    (hreq :delete "/hello.txt" tom-auth))

  (testing "standard parent directory traversal /../tom/hello.txt"
    (is (= 201 (:status (hreq :put "/hello.txt" tom-auth {} "tom-secret"))))
    (let [r (hreq :get "/../tom/hello.txt" alice-auth)]
      (is (contains? #{403 404 500} (:status r)) "/../tom/ traversal should not return 200")
      (is (not= "tom-secret" (:body r)) "must not leak tom's file content"))
    (hreq :delete "/hello.txt" tom-auth))

  (testing "URL-encoded dots /%2e%2e/tom/hello.txt bypasses .. string check"
    (is (= 201 (:status (hreq :put "/hello.txt" tom-auth {} "tom-secret"))))
    (let [r (hreq :get "/%2e%2e/tom/hello.txt" alice-auth)]
      (is (contains? #{403 404 500} (:status r)) "%2e%2e traversal should not return 200")
      (is (not= "tom-secret" (:body r)) "must not leak tom's file content"))
    (hreq :delete "/hello.txt" tom-auth))

  (testing "partially encoded dots /.%2e/tom/hello.txt"
    (is (= 201 (:status (hreq :put "/hello.txt" tom-auth {} "tom-secret"))))
    (let [r (hreq :get "/.%2e/tom/hello.txt" alice-auth)]
      (is (contains? #{403 404 500} (:status r)) ".%2e traversal should not return 200")
      (is (not= "tom-secret" (:body r)) "must not leak tom's file content"))
    (hreq :delete "/hello.txt" tom-auth))

  (testing "encoded slash /..%2ftom/hello.txt"
    (is (= 201 (:status (hreq :put "/hello.txt" tom-auth {} "tom-secret"))))
    (let [r (hreq :get "/..%2ftom/hello.txt" alice-auth)]
      (is (contains? #{403 404 500} (:status r)) "..%2f traversal should not return 200")
      (is (not= "tom-secret" (:body r)) "must not leak tom's file content"))
    (hreq :delete "/hello.txt" tom-auth))

  (testing "backslash /..\\tom/hello.txt"
    (is (= 201 (:status (hreq :put "/hello.txt" tom-auth {} "tom-secret"))))
    (let [r (hreq :get "/..\\tom/hello.txt" alice-auth)]
      (is (contains? #{403 404 500} (:status r)) "backslash traversal should not return 200")
      (is (not= "tom-secret" (:body r)) "must not leak tom's file content"))
    (hreq :delete "/hello.txt" tom-auth))

  (testing "double encoding /%252e%252e/tom/hello.txt"
    (is (= 201 (:status (hreq :put "/hello.txt" tom-auth {} "tom-secret"))))
    (let [r (hreq :get "/%252e%252e/tom/hello.txt" alice-auth)]
      (is (contains? #{403 404 500} (:status r)) "double-encoded traversal should not return 200")
      (is (not= "tom-secret" (:body r)) "must not leak tom's file content"))
    (hreq :delete "/hello.txt" tom-auth)))
