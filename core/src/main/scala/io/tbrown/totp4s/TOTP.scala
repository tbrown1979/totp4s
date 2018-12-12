package io.tbrown.totp4s

import cats.effect._
import cats.implicits._
import cats.kernel.Eq
import java.nio.ByteBuffer
import java.util.concurrent.TimeUnit
import javax.crypto.spec.SecretKeySpec

trait TOTP[F[_]] {
  def generatePassword(key: Secret): F[Code]
  def validate(code: Code, secret: Secret): F[Boolean]
}

object TOTP {
  def preconfigured[F[_]: Sync : Timer](digits: Digits, timeStep: TimeStep, window: Window, hmac: Hmac): TOTP[F] =
    new TOTP[F] {
      def generatePassword(key: Secret): F[Code] = genCode(key, digits, timeStep, hmac)
      def validate(code: Code, secret: Secret): F[Boolean] = checkCode(code, secret, timeStep, window, hmac)
    }

  private[this] def genCodeInternal[F[_]: Sync](key: Secret, digits: Digits, timeSteps: TimeSteps, hmac: Hmac): F[Code] = {
    val secretBytes = key.value.getBytes("UTF-8")

    for {
      data        <- Sync[F].delay(ByteBuffer.allocate(8).putLong(timeSteps.value).array())
      hash        <- HMAC_SHA(hmac, secretBytes, data)
      offset      <- Sync[F].catchNonFatal(hash(hash.length - 1) & 0xf)
      binary      <- Sync[F].catchNonFatal {
        ((hash(offset) & 0x7f) << 24) |
          ((hash(offset + 1) & 0xff) << 16) |
          ((hash(offset + 2) & 0xff) << 8) |
          (hash(offset + 3) & 0xff)
      }
      digitsPower <- Sync[F].catchNonFatal(DIGITS_POWER(digits.value))
    } yield {
      val code: String = padZeroes(((binary & 0x7FFFFFFF) % digitsPower).show, digits.value)
      Code(code)
    }
  }

  def genCode[F[_]: Sync : Timer](key: Secret, digits: Digits, timeStep: TimeStep, hmac: Hmac): F[Code] =
    Timer[F].clock.monotonic(TimeUnit.SECONDS).flatMap { seconds =>
      genCodeInternal(key, digits, TimeSteps(seconds / timeStep.value), hmac)
    }

  def checkCode[F[_]: Sync: Timer](code: Code, secret: Secret, timeStep: TimeStep, window: Window, hmac: Hmac): F[Boolean] =
    Timer[F].clock.monotonic(TimeUnit.SECONDS).flatMap { seconds =>
      Range(0, window.value).toList.existsM { i =>
        val timeSteps = TimeSteps((seconds - timeStep.value * i) / timeStep.value)
        genCodeInternal(secret, Digits(code.value.toString.length), timeSteps, hmac).map(_ === code)
      }
    }

  private[this] implicit val codeEq: Eq[Code] = Eq.fromUniversalEquals[Code]

  private[this] def HMAC_SHA[F[_]](hmac: Hmac, keyBytes: Array[Byte], text: Array[Byte])(implicit F: Sync[F]): F[Array[Byte]] =
    for {
      hmac   <- Hmac.mac(hmac)
      macKey <- F.delay(new SecretKeySpec(keyBytes, "RAW"))
      _      <- F.delay(hmac.init(macKey))
      done   <- F.delay(hmac.doFinal(text))
    } yield done

  private[this] val DIGITS_POWER: Vector[Int] =
    Vector(1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000)


  private[this] def padZeroes(value: String, endSize: Int): String = "".padTo(endSize - value.length, '0') + value
}