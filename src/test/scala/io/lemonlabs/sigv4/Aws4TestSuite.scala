package io.lemonlabs.sigv4

import java.io.File
import java.time.ZonedDateTime

import akka.actor.ActorSystem
import akka.http.impl.engine.parsing.TestRequestParser
import akka.http.scaladsl.Http
import akka.http.scaladsl.model.HttpHeader.ParsingResult.{Error, Ok}
import akka.http.scaladsl.model._
import akka.http.scaladsl.model.headers.RawHeader
import akka.stream.scaladsl.{Sink, Source}
import akka.stream.{ActorMaterializer, ActorMaterializerSettings}
import io.lemonlabs.sigv4.SignatureV4Signer.AwsCredentials
import org.scalatest.{FlatSpec, Matchers}

import scala.concurrent.Await
import scala.concurrent.duration._
/**
  * Runs the test suite from http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html
  */
class Aws4TestSuite extends FlatSpec with Matchers {

  val testDirectories: Vector[String] =
    new File(getClass.getResource("/aws4_testsuite").toURI)
      .listFiles()
      .toVector
      .filter(_.isDirectory)
      .map(_.getName)

  testDirectories should have size 24

  implicit val system: ActorSystem = ActorSystem("Aws4TestSuite")
  implicit val materializer: ActorMaterializer = ActorMaterializer(ActorMaterializerSettings(system))

  val requestParser = new TestRequestParser(system)

  def makeRequest(filename: String): HttpRequest = {
    val uri = getClass.getResource(filename).toURI
    val lines = scala.io.Source.fromURI(uri).getLines.toVector

    requestParser.parse(lines.mkString("\r\n"))

//    val Array(method, path, protocol) = lines.head.split(' ')
//
//    val headerLines = lines.tail.takeWhile(_.trim.nonEmpty)
//    val headers =  headerLines map { headerStr =>
//      val name = headerStr.takeWhile(_ != ':')
//      val value = headerStr.dropWhile(_ != ':').tail
//
//      HttpHeader.parse(name, value) match {
//        case Ok(header, _) => header
//        case Error(error) => fail(error.formatPretty)
//      }
//    }
//
//    val entityLines = lines.dropWhile(_.trim.nonEmpty).drop(1)
//    val entity = if(entityLines.nonEmpty) {
//      HttpEntity(entityLines.mkString("\n"))
//    } else {
//      HttpEntity.Empty
//    }
//
//    HttpRequest(HttpMethods.getForKey(method).head, path, headers, entity, HttpProtocols.getForKey(protocol).head)
  }

  def fileContents(filename: String): String = {
    val uri = getClass.getResource(filename).toURI
    val lines = scala.io.Source.fromURI(uri).getLines.toVector
    lines.mkString("\n")
  }

  testDirectories foreach { testDirectory =>
    try {
      testsFor(testDirectory)
    }
    catch {
      case t: Throwable => t.printStackTrace()
    }
  }

  def testsFor(testDirectory: String): Unit = {

    val request = makeRequest(s"/aws4_testsuite/$testDirectory/$testDirectory.req")
    val datetimeStr = request.headers.find(_.name == "X-Amz-Date").head.value
    val dateTime = ZonedDateTime.from(SignatureV4Signer.ISO_BASIC_DATE_TIME.parse(datetimeStr))

    // Part of this libraries functionality is to add the X-Amz-Date header, so let's remove it from the input request
    val requestAmzDateRemoved = request//.removeHeader("X-Amz-Date")

    // From http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html
    val credentialScope = "20150830/us-east-1/service/aws4_request"
    val creds = AwsCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", None)

    val signer = new SignatureV4Signer(Regions.usEast1, "service") {
      override protected def credentials = Source.repeat(creds)
      override def now: ZonedDateTime = dateTime
    }

    val signedHeaders = signer.makeSignedHeaders(requestAmzDateRemoved)
    val actualCanonicalRequest = signer.makeCanonicalRequest(requestAmzDateRemoved, signedHeaders)
    val actualStringToSign = signer.makeStringToSign(dateTime, actualCanonicalRequest, credentialScope)

    testDirectory should "match CanonicalRequest" in {
      val expectedCanonicalRequest = fileContents(s"/aws4_testsuite/$testDirectory/$testDirectory.creq")
      actualCanonicalRequest should equal(expectedCanonicalRequest)
    }

    testDirectory should "match StringToSign" in {
      val expectedStringToSign = fileContents(s"/aws4_testsuite/$testDirectory/$testDirectory.sts")
      actualStringToSign should equal(expectedStringToSign)
    }

    testDirectory should "match signed request" in {
      val actualSignedReq = signer.sign(requestAmzDateRemoved, creds)
      val expectedSignedRequest = makeRequest(s"/aws4_testsuite/$testDirectory/$testDirectory.sreq")

      actualSignedReq.method should equal(expectedSignedRequest.method)
      actualSignedReq.uri should equal(expectedSignedRequest.uri)
      actualSignedReq.protocol should equal(expectedSignedRequest.protocol)
      actualSignedReq.entity should equal(expectedSignedRequest.entity)

      expectedSignedRequest.headers foreach { expectedHeader =>
        val actualHeader = actualSignedReq.getHeader(expectedHeader.name).get
        actualHeader.value should equal(expectedHeader.value)
      }
    }
  }
}
