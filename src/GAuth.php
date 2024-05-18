<?php
    namespace Senestro88\gauth;
    /**
     * Google Authenticator
     * 
     * (c) John Yusuf Habila <Senestro88@gmail.com>
     * 
     * For the full copyright and license information, please view the LICENSE
     * file that was distributed with this source code.
     */
    class GAuth{
        /**
         * @var int
         */
        private $passCodeLength;

        /**
         * @var int
         */
        private $secretLength;

        /**
         * @var int
         */
        private $pinModulo;

        /**
         * @var \DateTimeInterface
         */
        private $instanceTime;

        /**
         * @var int
         */
        private $codePeriod;

        /**
         * @var int
         */
        private $periodSize = 30;

        public function __construct(int $passCodeLength = 6, int $secretLength = 10, ?\DateTimeInterface $instanceTime = null, int $codePeriod = 30){
            /*
             * codePeriod is the duration in seconds that the code is valid.
             * periodSize is the length of a period to calculate periods since Unix epoch.
             * periodSize cannot be larger than the codePeriod.
             */
            $this->passCodeLength = $passCodeLength;
            $this->secretLength = $secretLength;
            $this->codePeriod = $codePeriod;
            $this->periodSize = $codePeriod < $this->periodSize ? $codePeriod : $this->periodSize;
            $this->pinModulo = 10 ** $passCodeLength;
            $this->instanceTime = $instanceTime ?? new \DateTimeImmutable();
        }

        public function generateSecret(): string{
            return (new lib\FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', true, true))->encode(random_bytes($this->secretLength));
        }

        /**
         * @param string $user
         * @param string $hostname
         * @param string $issuer
         * @param string $secret
         */
        public function generateUrl(string $user, string $hostname, string $issuer, string $secret): string{
            $accountName = sprintf('%s@%s', $user, $hostname);
            $url = lib\QrCodeUrl::generate($accountName, $secret, $issuer);
            return $url;
        }
        
        /**
         * @param string $user
         * @param string $hostname
         * @param string $issuer
         * @param string $secret
         */
        public function generateImage(string $user, string $hostname, string $issuer, string$secret): string{
            $accountName = sprintf('%s@%s', $user, $hostname);
            $url = lib\QrCodeImage::generate($accountName, $secret, $issuer); 
            return $url;
        }

        /**
         * @param string $secret
         * @param \DateTimeInterface|null $time
         */
        public function getCode(string $secret, ?\DateTimeInterface $time = null): string{
            if (null === $time) {$time = $this->instanceTime; }
            if ($time instanceof \DateTimeInterface) {$timeForCode = floor($time->getTimestamp() / $this->periodSize);} else {$timeForCode = $time;}
            $base32 = new lib\FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', true, true);
            $secret = $base32->decode($secret);
            $timeForCode = str_pad(pack('N', $timeForCode), 8, \chr(0), \STR_PAD_LEFT);
            $hash = hash_hmac('sha1', $timeForCode, $secret, true);
            $offset = \ord(substr($hash, -1));
            $offset &= 0xF;
            $truncatedHash = $this->hashToInt($hash, $offset) & 0x7FFFFFFF;
            return str_pad((string) ($truncatedHash % $this->pinModulo), $this->passCodeLength, '0', \STR_PAD_LEFT);
        }

        /**
         * @param string $secret
         * @param string $code
         * @param int $discrepancy
         */
        public function checkCode(string $secret, string $code, int $discrepancy = 1): bool{
            /**
             * Discrepancy is the factor of periodSize ($discrepancy * $periodSize) allowed on either side of the
             * given codePeriod. For example, if a code with codePeriod = 60 is generated at 10:00:00, a discrepancy
             * of 1 will allow a periodSize of 30 seconds on either side of the codePeriod resulting in a valid code
             * from 09:59:30 to 10:00:29.
             *
             * The result of each comparison is stored as a timestamp here instead of using a guard clause
             * (https://refactoring.com/catalog/replaceNestedConditionalWithGuardClauses.html). This is to implement
             * constant time comparison to make side-channel attacks harder. See
             * https://cryptocoding.net/index.php/Coding_rules#Compare_secret_strings_in_constant_time for details.
             * Each comparison uses hash_equals() instead of an operator to implement constant time equality comparison
             * for each code.
             */
            $periods = floor($this->codePeriod / $this->periodSize);
            $result = 0;
            for ($i = -$discrepancy; $i < $periods + $discrepancy; ++$i) {
                $dateTime = new \DateTimeImmutable('@'.($this->instanceTime->getTimestamp() - ($i * $this->periodSize)));
                $result = hash_equals($this->getCode($secret, $dateTime), $code) ? $dateTime->getTimestamp() : $result;
            }
            return $result > 0;
        }

        private function hashToInt(string $bytes, int $start): int{
            return unpack('N', substr(substr($bytes, $start), 0, 4))[1];
        }
    }