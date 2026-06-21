(ns jj.kuoka.core
  (:require [jj.kuoka.handler :as h])
  (:import (java.io File)))

(defn make-handler
  "Create a WebDAV Ring handler.
   Args:
     root           - root directory for WebDAV files (required)
     admin-password - password for the admin principal
     users          - map of username->password (e.g. {\"alice\" \"p4ss\" \"bob\" \"b0b123\"})"
  [root admin-password users]
  (let [dir (File. ^String root)]
    (when-not (.exists dir) (.mkdirs dir))
    (let [state-atom (h/init-state root :admin-password admin-password)
          _ (doseq [[user pass] users] (h/add-user state-atom user pass))]
      (h/make-app state-atom))))
