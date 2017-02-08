package io.lemonlabs.sigv4

import akka.actor.{ActorLogging, ActorRef, ActorSystem, Props, Status}
import akka.http.scaladsl.Http
import akka.http.scaladsl.model.{HttpEntity, HttpRequest}
import akka.pattern.pipe
import akka.stream.actor.ActorPublisher
import akka.stream.actor.ActorPublisherMessage.{Cancel, Request}
import akka.stream.scaladsl.Source
import akka.stream.{ActorMaterializer, ActorMaterializerSettings}
import akka.util.ByteString
import io.lemonlabs.sigv4.Ec2CredentialsRetriever.UpdateCredentials
import io.lemonlabs.sigv4.Regions.Region
import io.lemonlabs.sigv4.Services.Service
import io.lemonlabs.sigv4.SignatureV4Signer.AwsCredentials
import spray.json.{JsString, _}

import scala.concurrent.ExecutionContext
import scala.concurrent.duration._
import scala.util.{Failure, Success, Try}

class Ec2InstanceSigner(region: Region, service: Service, roleName: String, system: ActorSystem) extends SignatureV4Signer(region, service) {
  protected val credentials: Source[AwsCredentials, ActorRef] =
    Source.actorPublisher[AwsCredentials](Props(classOf[Ec2CredentialsRetriever], roleName))
}

object Ec2CredentialsRetriever {
  private case object UpdateCredentials
}
class Ec2CredentialsRetriever(roleName: String) extends ActorPublisher[AwsCredentials] with ActorLogging {

  implicit val materializer: ActorMaterializer = ActorMaterializer(ActorMaterializerSettings(context.system))

  def config = context.system.settings.config
  val readTimeout = config.getDuration("sigv4.ec2.read-timeout").toMillis.millis
  val updateInterval = config.getDuration("sigv4.ec2.update-interval").toMillis.millis
  val noCredsRetry = config.getDuration("sigv4.ec2.no-credentials-retry").toMillis.millis
  val credsBaseUrl = config.getString("sigv4.ec2.security-credentials-base-url")

  var currentCredentials = Option.empty[AwsCredentials]

  context.system.scheduler.schedule(0.seconds, updateInterval, self, UpdateCredentials)

  implicit def ec: ExecutionContext = context.system.dispatcher

  def receive: Receive = {
    case Request(_) =>
      publish()

    case UpdateCredentials =>
      requestCredentials()

    case HttpEntity.Strict(_, data) =>
      extractCredentials(data) match {
        case Success(creds) =>
          currentCredentials = Some(creds)
          publish()
        case Failure(e) =>
          updateCredentialsError(e)
      }

    case Status.Failure(e) =>
      updateCredentialsError(e)

    case Cancel =>
      context.stop(self)
  }

  def publish(): Unit = if(totalDemand > 0) {
    currentCredentials match {
      case Some(creds) =>
        (1l to totalDemand).foreach(i => onNext(creds))
      case _ =>
        () // We don't have the credentials yet... We'll send them when we get them.
    }
  }

  def updateCredentialsError(t: Throwable): Unit = {
    if(currentCredentials.isEmpty) {
      log.error(t, "Unable to update EC2 Credentials for role {}. Cache is empty, so retrying in {}", roleName, noCredsRetry)
      context.system.scheduler.scheduleOnce(noCredsRetry, self, UpdateCredentials)
    }
    else {
      log.error(t, "Unable to update EC2 Credentials for role {}", roleName)
    }
  }

  def requestCredentials(): Unit = {
    val request = HttpRequest(uri = credsBaseUrl + roleName)
    val responseEntity = Http(context.system).singleRequest(request).flatMap(_.entity.toStrict(readTimeout))
    responseEntity pipeTo self
  }

  def extractCredentials(data: ByteString): Try[AwsCredentials] = Try {
    val json = data.decodeString("UTF-8").parseJson.asJsObject
    val JsString(accessKeyId) = json.fields("AccessKeyId")
    val JsString(secretAccessKey) = json.fields("SecretAccessKey")
    val token = json.fields.get("Token").collect { case JsString(t) => t }
    AwsCredentials(accessKeyId, secretAccessKey, token)
  }
}
