<?php

declare(strict_types=1);

namespace Passless\Support\Exception;

/**
 * Indicates a failure while sending email through the configured provider.
 */
class MailTransportException extends PasslessException
{
}
