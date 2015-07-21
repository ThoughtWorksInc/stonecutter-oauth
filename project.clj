(defproject stonecutter-oauth "0.1.0-SNAPSHOT"
  :description "Client library for interacting with Stonecutter OAuth Server (see https://github.com/ThoughtWorksInc/stonecutter)"
  :url "https://github.com/ThoughtWorksInc/stonecutter-oauth"
  :min-lein-version "2.0.0"
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [clj-http "1.1.2"]
                 [cheshire "5.5.0"]
                 [ring/ring-core "1.4.0"]]
  :profiles {:dev {:dependencies   [[midje "1.6.3"]]
                   :plugins        [[lein-midje "3.1.3"]]}})
