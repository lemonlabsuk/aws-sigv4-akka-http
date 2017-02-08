package io.lemonlabs.sigv4

import java.security.MessageDigest
import java.time.format.{DateTimeFormatter, DateTimeFormatterBuilder}
import java.time.temporal.ChronoField._
import java.time.{Clock, ZonedDateTime}
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import akka.NotUsed
import akka.actor.ActorSystem
import akka.http.scaladsl.model.HttpEntity.Strict
import akka.http.scaladsl.model.headers._
import akka.http.scaladsl.model.{HttpCharsets, HttpRequest}
import akka.stream.scaladsl.{Flow, Source}
import io.lemonlabs.sigv4.Regions.Region
import io.lemonlabs.sigv4.Services.Service
import io.lemonlabs.sigv4.SignatureV4Signer.{AwsCredentials, _}

object SignatureV4Signer {

  val ISO_BASIC_DATE: DateTimeFormatter = new DateTimeFormatterBuilder()
      .parseCaseInsensitive()
      .appendValue(YEAR, 4)
      .appendValue(MONTH_OF_YEAR, 2)
      .appendValue(DAY_OF_MONTH, 2)
      .toFormatter()

  val ISO_BASIC_DATE_TIME: DateTimeFormatter = new DateTimeFormatterBuilder()
      .parseCaseInsensitive()
      .append(ISO_BASIC_DATE)
      .appendLiteral('T')
      .appendValue(HOUR_OF_DAY, 2)
      .appendValue(MINUTE_OF_HOUR, 2)
      .appendValue(SECOND_OF_MINUTE, 2)
      .appendOffsetId()
      .toFormatter()


  case class AwsCredentials(accessKeyId: String, secretAccessKey: String, token: Option[String])

  def basic(region: Region, service: Service, accessKeyId: String, secretAccessKey: String) =
    new SignatureV4Signer(region, service) {
      protected val credentials = Source.repeat(AwsCredentials(accessKeyId, secretAccessKey, None))
    }

  def environmentVariables(region: Region, service: Service) =
    basic(region, service, sys.env("AWS_ACCESS_KEY_ID"), sys.env("AWS_SECRET_ACCESS_KEY"))

  def ec2Instance(region: Region, service: Service, roleName: String)(implicit system: ActorSystem) =
    new Ec2InstanceSigner(region, service, roleName, system)
}

abstract class SignatureV4Signer(region: Region, service: Service) {

  protected def credentials: Source[AwsCredentials, Any]

  def signFlow: Flow[HttpRequest, HttpRequest, NotUsed] = Flow[HttpRequest].zip(credentials).map {
    case (request, creds) => sign(request, creds)
  }

  protected[sigv4] def sign(rBefore: HttpRequest, creds: AwsCredentials): HttpRequest = {
    val AwsCredentials(accessKeyId, secretAccessKey, token) = creds

    // Add the host header if it is missing
    val r =
      if(rBefore.header[Host].nonEmpty)
        rBefore
      else
        rBefore.copy(headers = rBefore.headers :+ Host(rBefore.uri.authority.host.address))

    val auth = authHeader(r, now, accessKeyId, secretAccessKey)
    val maybeTokenHeader = token.map(t => RawHeader("X-Amz-Security-Token", t))
    val otherHeaders =
      auth +:
      r.headers :+
      RawHeader("X-Amz-Date", now.format(ISO_BASIC_DATE_TIME))

    r.copy(headers = otherHeaders ++ maybeTokenHeader)
  }

  private def authHeader(r: HttpRequest, date: ZonedDateTime, accessKeyId: String, secretAccessKey: String): Authorization = {
    val signedHeaders = makeSignedHeaders(r)
    val canonicalRequest = makeCanonicalRequest(r, signedHeaders)

    val dateString = date.format(ISO_BASIC_DATE)
    val credentialScope = s"$dateString/$region/$service/aws4_request"
    val stringToSign = makeStringToSign(date, canonicalRequest, credentialScope)

    val kDate = hmacSha256(dateString, ("AWS4" + secretAccessKey).getBytes("UTF-8"))
    val kRegion = hmacSha256(region, kDate)
    val kService = hmacSha256(service, kRegion)
    val kSigning = hmacSha256("aws4_request", kService)

    val signature = hex(hmacSha256(stringToSign, kSigning))

    Authorization(GenericHttpCredentials("AWS4-HMAC-SHA256", s"Credential=$accessKeyId/$credentialScope, SignedHeaders=$signedHeaders, Signature=$signature"))
  }

  protected[sigv4] def makeStringToSign(date: ZonedDateTime, canonicalRequest: String, credentialScope: String) = {
    "AWS4-HMAC-SHA256\n" +
    date.format(ISO_BASIC_DATE_TIME) + "\n" +
    credentialScope + "\n" +
    hex(sha256(canonicalRequest.getBytes("UTF-8")))
  }

  protected[sigv4] def makeCanonicalRequest(r: HttpRequest, signedHeaders: String) = {
    val content = r.entity match {
      case Strict(ct, data) =>
        val charset = ct.charsetOption.getOrElse(HttpCharsets.`UTF-8`)
        data.utf8String.getBytes(charset.value)
      case _ => Array.emptyByteArray
    }

    r.method.value + "\n" +
      r.uri.path + "\n" +
      r.uri.query().sortBy(_._1).toString().replaceAll("&", "&\n") + "\n" +
      r.headers.sortBy(_.name()).map(h => h.lowercaseName() + ":" + h.value() + "\n").mkString + "\n" +
      signedHeaders + "\n" +
      hex(sha256(content))
  }

  protected[sigv4] def makeSignedHeaders(r: HttpRequest) = {
    r.headers.sortBy(_.name()).map(_.lowercaseName()).mkString(";")
  }

  private def hex(bytes: Array[Byte]): String =
    bytes.map("%02X" format _).mkString.toLowerCase

  private def sha256(bytes: Array[Byte]): Array[Byte] = {
    val md = MessageDigest.getInstance("SHA-256")
    md.digest(bytes)
  }

  private def hmacSha256(str: String, secret: Array[Byte]): Array[Byte] =
    hmacSha256(str.getBytes("UTF-8"), secret)

  private def hmacSha256(bytes: Array[Byte], secret: Array[Byte]): Array[Byte] = {
    val signingKey = new SecretKeySpec(secret, "HmacSHA256")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(signingKey)
    mac.doFinal(bytes)
  }

  def now = ZonedDateTime.now(Clock.systemUTC())
}
