(defproject org.clojars.jj/kuoka "1.0.0"
  :description "kuoka isa webdav handler for clojure ring."
  :url "https://github.com/ruroru/kuoka"
  :license {:name "Eclipse Public License 2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.12.0"]
                 [org.clojure/data.xml "0.2.0-alpha11"]]
  :profiles {:test {:dependencies [[hato/hato "0.9.0"]
                                   [org.clojars.jj/ring-http-exchange "1.4.8"]]}}


  :deploy-repositories [["clojars" {:url      "https://repo.clojars.org"
                                    :sign-releases false
                                    :username :env/clojars_user
                                    :password :env/clojars_pass}]]

  :plugins [[org.clojars.jj/bump "1.0.4"]
            [org.clojars.jj/bump-md "1.1.0"]
            [org.clojars.jj/lein-git-tag "1.0.1"]
            [org.clojars.jj/strict-check "1.1.0"]]

  )
