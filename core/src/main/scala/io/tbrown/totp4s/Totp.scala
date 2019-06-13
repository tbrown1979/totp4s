package io.tbrown.totp4s

import cats.effect._
import cats.implicits._
import cats.kernel.Eq
import java.nio.ByteBuffer
import java.util.concurrent.TimeUnit
import javax.crypto.spec.SecretKeySpec
import eu.timepit.refined._
import eu.timepit.refined.api.Refined
import eu.timepit.refined.api.RefType
import eu.timepit.refined.numeric.Interval

trait Totp[F[_]] {
  def generatePassword(key: Secret): F[Code]
  def validate(code: Code, secret: Secret): F[Boolean]
}

object Totp {
  def preconfigured[F[_]: Sync : Timer](digits: Digits, timeStep: TimeStep, window: Window, hmac: Hmac): Totp[F] =
    new Totp[F] {
      def generatePassword(key: Secret): F[Code] = genCode(key, digits, timeStep, hmac)
      def validate(code: Code, secret: Secret): F[Boolean] = checkCode(code, secret, timeStep, window, hmac)
    }

  def genCode[F[_]: Sync : Timer](key: Secret, digits: Digits, timeStep: TimeStep, hmac: Hmac): F[Code] =
    Timer[F].clock.realTime(TimeUnit.SECONDS).flatMap { seconds =>
      genCodeInternal(key, digits, TimeSteps(seconds / timeStep.value), hmac)
    }

  def checkCode[F[_]: Sync: Timer](code: Code, secret: Secret, timeStep: TimeStep, window: Window, hmac: Hmac): F[Boolean] =
    for {
      seconds <- Timer[F].clock.realTime(TimeUnit.SECONDS)
      digits  <- Sync[F].fromEither(RefType.applyRef[Digits](code.value.toString.length).leftMap(InvalidCodeFormat))
      valid   <- List.range(0, window.value).existsM { i =>
        val timeSteps = TimeSteps((seconds - timeStep.value * i) / timeStep.value)
        genCodeInternal(secret, digits, timeSteps, hmac).map(_ === code)
      }
    } yield valid

  private[this] def genCodeInternal[F[_]: Sync](key: Secret, digits: Digits, timeSteps: TimeSteps, hmac: Hmac): F[Code] = {
    val secretBytes = key.value.getBytes("UTF-8")

    for {
      data        <- Sync[F].delay(ByteBuffer.allocate(8).putLong(timeSteps.value).array())
      hash        <- hmacSha(hmac, secretBytes, data)
      offset      <- Sync[F].catchNonFatal(hash(hash.length - 1) & 0xf)
      binary      <- Sync[F].catchNonFatal {
        ((hash(offset) & 0x7f) << 24) |
          ((hash(offset + 1) & 0xff) << 16) |
          ((hash(offset + 2) & 0xff) << 8) |
          (hash(offset + 3) & 0xff)
      }
      digitsPower <- Sync[F].fromEither(digitsPower(digits))
    } yield {
      val code: String = padZeroes(((binary & 0x7FFFFFFF) % digitsPower).show, digits.value)
      Code(code)
    }
  }

  //how high can this actually go?
  type Digits = Int Refined Interval.Closed[W.`6`.T, W.`8`.T]

  private[this] implicit val codeEq: Eq[Code] = Eq.fromUniversalEquals[Code]

  private[this] def digitsPower(digits: Digits): Either[Throwable, Int] =
    Either.catchNonFatal( ("1" + "0" * digits.value).toInt )

  private[this] def padZeroes(value: String, endSize: Int): String = "".padTo(endSize - value.length, '0') + value

  private[this] def hmacSha[F[_]](hmac: Hmac, keyBytes: Array[Byte], text: Array[Byte])(implicit F: Sync[F]): F[Array[Byte]] =
    for {
      hmac   <- Hmac.mac(hmac)
      macKey <- F.delay(new SecretKeySpec(keyBytes, "RAW"))
      _      <- F.delay(hmac.init(macKey))
      done   <- F.delay(hmac.doFinal(text))
    } yield done
}