<?php
/*
 * This file is part of the PHPMaster88 Project package.
 *
 * (c) John Yusuf Habila <Senestro88@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Senestro88\gauth\lib;

/**
 * Contains runtime exception templates.
 *
 * @author Iltar van der Berg <kjarli@gmail.com>
 */
class QrException extends \RuntimeException{
    public static function InvalidAccountName(string $accountName): self {
        return new self(sprintf(
            'The account name may not contain a double colon (:) and may not be an empty string. Given "%s".',
            $accountName
        ));
    }

    public static function InvalidIssuer(string $issuer): self{
        return new self(sprintf(
            'The issuer name may not contain a double colon (:) and may not be an empty string. Given "%s".',
            $issuer
        ));
    }

    public static function InvalidSecret(): self{
        return new self('The secret name may not be an empty string.');
    }
}