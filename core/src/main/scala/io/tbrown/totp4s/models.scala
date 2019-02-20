package io.tbrown.totp4s
import scala.util.control.NoStackTrace

case class Code(value: String) extends AnyVal //6-8 digit TOTP password
case class Secret(value: String) extends AnyVal //secret used to generate the TOTP
case class Window(value: Int) extends AnyVal //How many timesteps the TOTP will be checked against for validation
case class TimeStep(value: Long) extends AnyVal //seconds range that the TOTP is valid for
case class TimeSteps(value: Long) extends AnyVal // number of TimeSteps for the current UNIX time, this divided by TimeStep

case class InvalidCodeFormat(msg: String) extends RuntimeException with NoStackTrace
