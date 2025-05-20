// build.sbt
val scala3Version = "3.3.3"

lazy val root = project
  .in(file("."))
  .enablePlugins(ScalaJSPlugin)
  .settings(
    name := "sonny-ui",
    version := "0.1.0",
    scalaVersion := scala3Version,
    scalaJSUseMainModuleInitializer := true,
    scalaJSLinkerConfig ~= (_.withModuleKind(ModuleKind.ESModule)),
    libraryDependencies ++= Seq(
      "io.indigoengine" %%% "tyrian-io" % "0.10.0",
      "io.circe" %%% "circe-core" % "0.14.6",
      "io.circe" %%% "circe-generic" % "0.14.6",
      "io.circe" %%% "circe-parser" % "0.14.6",
      "io.indigoengine" %%% "tyrian" % "0.10.0",       // Core Tyrian
      "org.typelevel" %%% "cats-effect" % "3.5.4",      // Required for subscriptions
      "org.scalameta" %%% "munit" % "1.0.0-M10" % Test
    )
  )