package akka.http.impl.engine.parsing

import akka.actor.ActorSystem
import akka.http.impl.engine.parsing.ParserOutput.RequestStart
import akka.http.scaladsl.model.{HttpEntity, HttpRequest}
import akka.http.scaladsl.settings.ParserSettings
import akka.stream.Materializer
import akka.stream.TLSProtocol.SessionBytes
import akka.stream.scaladsl.{Sink, Source, TLSPlacebo}
import akka.util.ByteString

import scala.concurrent.Await
import scala.concurrent.duration._

class TestRequestParser(system: ActorSystem)(implicit val materializer: Materializer) {

  private val parserSettings = ParserSettings(system)
  val parserFlow = new HttpRequestParser(parserSettings, false, HttpHeaderParser(parserSettings, system.log)())

  def parse(requestStr: String): HttpRequest = {

    val entityStart = requestStr.indexOf("\r\n\r\n")
//    val requestStartStr = if(entityStart == -1) requestStr else requestStr.substring(0, entityStart)

    val requestOutputF = Source.single(SessionBytes(TLSPlacebo.dummySession, ByteString(requestStr)))
      .via(parserFlow)
      .runWith(Sink.seq)

    Await.result(requestOutputF, 5.seconds).head match {
      case RequestStart(method, uri, protocol, headers, createEntity, _, _) =>
        val entity = if(entityStart == -1) HttpEntity.Empty else HttpEntity(requestStr.substring(entityStart + 4))
        HttpRequest(method, uri, headers, entity, protocol)
      case x =>
        throw new IllegalArgumentException("Expected RequestStart, got " + x)
    }
  }
}
