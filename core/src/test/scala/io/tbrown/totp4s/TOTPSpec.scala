package io.tbrown.totp4s

import cats.effect.{Clock, IO, Sync, Timer}
import org.specs2.mutable.Specification

import scala.concurrent.duration.{FiniteDuration, TimeUnit}

class TOTPSpec extends Specification {
  import TOTP._

  def testTimer(time: Long): Timer[IO] = new Timer[IO] {
    override def clock: Clock[IO] = new Clock[IO] {
      override def realTime(unit: TimeUnit): IO[Long] = ???

      override def monotonic(unit: TimeUnit): IO[Long] = IO(time)
    }

    override def sleep(duration: FiniteDuration): IO[Unit] = ???
  }

  val window = Window(3)

  val defaultTimeStep = TimeStep(30)

  "TOTPSpec" should {
    "succeed when time matches" in {
      val secret = Secret("something random")
      implicit val t = testTimer(0)

      val genned = genCode[IO](secret, Digits(6), defaultTimeStep, HmacSha1).unsafeRunSync
      checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha1).unsafeRunSync must beTrue
    }

    "Window tests" should {
      "succeed when we're one timeStep away from the generated one" in {
        val secret = Secret("something random")
        val t = testTimer(0)
        val t2 = testTimer(30)

        val genned = genCode[IO](secret, Digits(6), defaultTimeStep, HmacSha1)(Sync[IO], t).unsafeRunSync
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha1)(Sync[IO], t2).unsafeRunSync must beTrue
      }

      "succeed when we're two timesteps away from the the generated one" in {
        val secret = Secret("something random")
        val t = testTimer(0)
        val t2 = testTimer(60)

        val genned = genCode[IO](secret, Digits(6), defaultTimeStep, HmacSha1)(Sync[IO], t).unsafeRunSync
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha1)(Sync[IO], t2).unsafeRunSync must beTrue
      }

      "succeed when we're within two timesteps away from the generated one" in {
        val secret = Secret("something random")
        val t = testTimer(0)
        val t2 = testTimer(61)

        val genned = genCode[IO](secret, Digits(6), defaultTimeStep, HmacSha1)(Sync[IO], t).unsafeRunSync
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha1)(Sync[IO], t2).unsafeRunSync must beTrue
      }

      "fail when we're more than two timesteps away from the generated one" in {
        val secret = Secret("something random")
        val t = testTimer(0)
        val t2 = testTimer(90)

        val genned = genCode[IO](secret, Digits(6), defaultTimeStep, HmacSha1)(Sync[IO], t).unsafeRunSync
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha1)(Sync[IO], t2).unsafeRunSync must beFalse
      }
    }



    "RFC Sha-1" should {
      //converted from HEX in the RFC
      val secret = Secret("12345678901234567890")

      "pass example #1" in {
        implicit val t = testTimer(59)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha1).unsafeRunSync
        genned must_== Code("94287082")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha1).unsafeRunSync must beTrue
      }

      "pass example #2" in {
        implicit val t = testTimer(1111111109L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha1).unsafeRunSync
        genned must_== Code("07081804")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha1).unsafeRunSync must beTrue
      }

      "pass example #3" in {
        implicit val t = testTimer(1111111111L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha1).unsafeRunSync
        genned must_== Code("14050471")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha1).unsafeRunSync must beTrue
      }

      "pass example #4" in {
        implicit val t = testTimer(1234567890L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha1).unsafeRunSync
        genned must_== Code("89005924")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha1).unsafeRunSync must beTrue
      }

      "pass example #5" in {
        implicit val t = testTimer(2000000000L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha1).unsafeRunSync
        genned must_== Code("69279037")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha1).unsafeRunSync must beTrue
      }

      "pass example #6" in {
        implicit val t = testTimer(20000000000L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha1).unsafeRunSync
        genned must_== Code("65353130")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha1).unsafeRunSync must beTrue
      }
    }

    "RFC Sha-256" should {
      //converted from HEX in the RFC
      val secret = Secret("12345678901234567890123456789012")

      "pass example #1" in {
        implicit val t = testTimer(59)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha256).unsafeRunSync
        genned must_== Code("46119246")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha256).unsafeRunSync must beTrue
      }

      "pass example #2" in {
        implicit val t = testTimer(1111111109L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha256).unsafeRunSync
        genned must_== Code("68084774")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha256).unsafeRunSync must beTrue
      }

      "pass example #3" in {
        implicit val t = testTimer(1111111111L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha256).unsafeRunSync
        genned must_== Code("67062674")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha256).unsafeRunSync must beTrue
      }

      "pass example #4" in {
        implicit val t = testTimer(1234567890L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha256).unsafeRunSync
        genned must_== Code("91819424")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha256).unsafeRunSync must beTrue
      }

      "pass example #5" in {
        implicit val t = testTimer(2000000000L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha256).unsafeRunSync
        genned must_== Code("90698825")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha256).unsafeRunSync must beTrue
      }

      "pass example #6" in {
        implicit val t = testTimer(20000000000L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha256).unsafeRunSync
        genned must_== Code("77737706")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha256).unsafeRunSync must beTrue
      }
    }

    "RFC Sha-512" should {
      //converted from HEX in the RFC
      val secret = Secret("1234567890123456789012345678901234567890123456789012345678901234")

      "pass example #1" in {
        implicit val t = testTimer(59)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha512).unsafeRunSync
        genned must_== Code("90693936")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha512).unsafeRunSync must beTrue
      }

      "pass example #2" in {
        implicit val t = testTimer(1111111109L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha512).unsafeRunSync
        genned must_== Code("25091201")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha512).unsafeRunSync must beTrue
      }

      "pass example #3" in {
        implicit val t = testTimer(1111111111L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha512).unsafeRunSync
        genned must_== Code("99943326")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha512).unsafeRunSync must beTrue
      }

      "pass example #4" in {
        implicit val t = testTimer(1234567890L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha512).unsafeRunSync
        genned must_== Code("93441116")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha512).unsafeRunSync must beTrue
      }

      "pass example #5" in {
        implicit val t = testTimer(2000000000L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha512).unsafeRunSync
        genned must_== Code("38618901")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha512).unsafeRunSync must beTrue
      }

      "pass example #6" in {
        implicit val t = testTimer(20000000000L)

        val genned = genCode[IO](secret, Digits(8), defaultTimeStep, HmacSha512).unsafeRunSync
        genned must_== Code("47863826")
        checkCode[IO](genned, secret, defaultTimeStep, window, HmacSha512).unsafeRunSync must beTrue
      }
    }
  }
}