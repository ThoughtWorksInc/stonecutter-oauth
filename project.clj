(defproject org.clojars.d-cent/stonecutter-oauth "0.1.9-SNAPSHOT"
  :description "Client library for interacting with Stonecutter OAuth Server (see https://github.com/ThoughtWorksInc/stonecutter)"
  :url "https://github.com/ThoughtWorksInc/stonecutter-oauth"
  :min-lein-version "2.0.0"
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [clj-http "1.1.2"]
                 [cheshire "5.5.0"]
                 [org.bitbucket.b_c/jose4j "0.4.4"]
                 [org.slf4j/slf4j-simple "1.7.12"] 
                 [ring/ring-core "1.4.0"]]
  :profiles {:dev {:dependencies   [[midje "1.6.3"]]
                   :plugins        [[lein-midje "3.1.3"]]}}
  :deploy-repositories [["clojars" {:username :env
                                    :password :env}]])
