name := "aws-sigv4-akka-http"

organization  := "io.lemonlabs"

version       := "1.0.0"

scalaVersion  := "2.12.1"

libraryDependencies ++=
    "com.typesafe.akka" %% "akka-http" % "10.0.3" ::
    "com.typesafe.akka" %% "akka-http-spray-json" % "10.0.3" ::
    "io.spray" %%  "spray-json" % "1.3.2" :: Nil

// Test Dependencies
libraryDependencies ++=
  "org.scalatest" %% "scalatest" % "3.0.0" % "test" :: Nil
