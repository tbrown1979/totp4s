package io.tbrown.totp4s

import cats.effect._
import javax.crypto.Mac

sealed trait Hmac
case object HmacSha1 extends Hmac
case object HmacSha256 extends Hmac
case object HmacSha512 extends Hmac

object Hmac {
  def mac[F[_]: Sync](hmac: Hmac): F[Mac] = {
    val s = hmac match {
      case HmacSha1 => "HmacSHA1"
      case HmacSha256 => "HmacSHA256"
      case HmacSha512 => "HmacSHA512"
    }

    Sync[F].delay(Mac.getInstance(s))
  }
}