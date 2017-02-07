package io.lemonlabs.sigv4

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import akka.NotUsed
import akka.actor.ActorSystem
import akka.http.scaladsl.model.HttpEntity.Strict
import akka.http.scaladsl.model.headers._
import akka.http.scaladsl.model.{DateTime, HttpCharsets, HttpRequest}
import akka.stream.scaladsl.{Flow, Source}
import io.lemonlabs.sigv4.SignatureV4Signer.AwsCredentials

object SignatureV4Signer {
  case class AwsCredentials(accessKeyId: String, secretAccessKey: String, token: Option[String])

  def basic(accessKeyId: String, secretAccessKey: String) = new SignatureV4Signer {
    protected val credentials = Source.repeat(AwsCredentials(accessKeyId, secretAccessKey, None))
  }

  def environmentVariables() =
    basic(sys.env("AWS_ACCESS_KEY_ID"), sys.env("AWS_SECRET_ACCESS_KEY"))

  def ec2Instance(roleName: String)(implicit system: ActorSystem) = new Ec2InstanceSigner(roleName, system)
}

trait SignatureV4Signer {

  protected def credentials: Source[AwsCredentials, Any]

  def signFlow: Flow[HttpRequest, HttpRequest, NotUsed] = Flow[HttpRequest].zip(credentials).map {
    case (request, creds) => sign(request, creds)
  }

  protected def sign(rBefore: HttpRequest, creds: AwsCredentials): HttpRequest = {

    val AwsCredentials(accessKeyId, secretAccessKey, token) = creds

    val r = rBefore.copy(headers = rBefore.headers :+ Host(rBefore.uri.authority.host.address()))

    val now = DateTime(currentTimeMillis)
    val auth = authHeader(r, now, accessKeyId, secretAccessKey)

    val maybeTokenHeader = token.map(t => RawHeader("X-Amz-Security-Token", t))
    val otherHeaders =
      auth +:
      r.headers :+
      RawHeader("X-Amz-Date", now.toIsoDateTimeString().replace("-", "").replace(":", "") + "Z") //TODO: remove replace

    r.copy(headers = otherHeaders ++ maybeTokenHeader)
  }

  private def authHeader(r: HttpRequest, date: DateTime, accessKeyId: String, secretAccessKey: String): Authorization = {
    val content = r.entity match {
      case Strict(ct, data) =>
        val charset = ct.charsetOption.getOrElse(HttpCharsets.`UTF-8`)
        data.utf8String.getBytes(charset.value)
      case _ => Array.emptyByteArray
    }

    val signedHeaders = r.headers.sortBy(_.name()).map(_.lowercaseName()).mkString(";")

    val canonicalRequest =
      r.method.value + "\n" +
      r.uri.path + "\n" +
      r.uri.query().sortBy(_._1).toString().replaceAll("&", "&\n") + "\n" + // TODO: Make better
      r.headers.sortBy(_.name()).map(h => h.lowercaseName() + ":" + h.value() + "\n").mkString + "\n" +
      signedHeaders + "\n" +
      hex(sha256(content))

    println("CR")
    println(canonicalRequest)

    val dateString = date.toIsoDateString().replace("-", "") // TODO: Fix replace
    val credentialScope = dateString + "/eu-west-1/es/aws4_request" // TODO: Fix hardcoded region+service

    val stringToSign =
      "AWS4-HMAC-SHA256\n" +
      date.toIsoDateTimeString().replace("-", "").replace(":", "") + "Z\n" + // TODO: Fix replace
      credentialScope + "\n" +
      hex(sha256(canonicalRequest.getBytes("UTF-8")))

    println("STS")
    println(stringToSign)

    val kDate = hmacSha256(dateString, ("AWS4" + secretAccessKey).getBytes("UTF-8"))
    val kRegion = hmacSha256("eu-west-1", kDate)
    val kService = hmacSha256("es", kRegion)
    val kSigning = hmacSha256("aws4_request", kService)

    val signature = hex(hmacSha256(stringToSign, kSigning))

    Authorization(GenericHttpCredentials("AWS4-HMAC-SHA256", s"Credential=$accessKeyId/$credentialScope, SignedHeaders=$signedHeaders, Signature=$signature"))
  }

  private def hex(bytes: Array[Byte]): String = {
    bytes.map("%02X" format _).mkString.toLowerCase
  }

  private def sha256(bytes: Array[Byte]): Array[Byte] = {
    val md = MessageDigest.getInstance("SHA-256")
    md.digest(bytes)
  }

  private def hmacSha256(str: String, secret: Array[Byte]): Array[Byte] = hmacSha256(str.getBytes("UTF-8"), secret)

  private def hmacSha256(bytes: Array[Byte], secret: Array[Byte]): Array[Byte] = {
    val signingKey = new SecretKeySpec(secret, "HmacSHA256")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(signingKey)
    mac.doFinal(bytes)
  }

  def currentTimeMillis = System.currentTimeMillis

}
