<?php

namespace Composer\Test\Util\RemoteFilesystem;

use Symfony\Component\Process\Process;
use Symfony\Component\Process\ProcessBuilder;

final class TlsServer
{
    private $host = 'localhost';
    private $port;
    private $certificate;
    private $key;
    private $ca;
    private $responses;
    /* @var string Cipher order, Mozilla intermediate */
    private $ciphers = 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
    private $process;


    public static function createSelfSignedLocalhost()
    {
        return new self(
            __DIR__.'/self-signed-localhost-cert.pem',
            __DIR__.'/self-signed-localhost-key.pem'
        );
    }

    public static function createSelfSignedGarbage()
    {
        return new self(
            __DIR__.'/self-signed-garbage-cert.pem',
            __DIR__.'/self-signed-garbage-key.pem'
        );
    }

    public static function createSignedLocalhost($intermediate, $chain)
    {
        $server = new self(
            __DIR__."/ca/$intermediate/certs/localhost.cert.pem",
            __DIR__."/ca/$intermediate/private/localhost.key.pem"
        );

        if ($chain) {
            $server->ca(__DIR__."/ca/$intermediate/certs/intermediate.cert.pem");
        }

        return $server;
    }

    public static function createSignedNipIo($host, $intermediate, $chain)
    {
        $cn = '127.0.0.1.nip.io';
        $host = $host ? "$host.$cn" : $cn;

        $server = new self(
            __DIR__."/ca/$intermediate/certs/$cn.cert.pem",
            __DIR__."/ca/$intermediate/private/$cn.key.pem"
        );

        if ($chain) {
            $server->ca(__DIR__."/ca/$intermediate/certs/intermediate.cert.pem");
        }

        $server->host($host);

        return $server;
    }

    public function __construct($certificate, $key, $port = null)
    {
        $this->certificate = $certificate;
        $this->key = $key;
        $this->port = $port ?: mt_rand(61001, 65535);
    }

    public function __clone()
    {
        $this->process = null;
    }

    public function __destruct()
    {
        $this->stop();
    }

    /**
     * Set hostname used in URLs.
     */
    public function host($host)
    {
        $this->host = $host;

        return $this;
    }

    /**
     * Port number to be used by the server.
     */
    public function port($port)
    {
        $this->port = $port;

        return $this;
    }

    /**
     * Set path to certificate(s) that are used for validation clients and building the chain.
     */
    public function ca($path)
    {
        $this->ca = $path;

        return $this;
    }

    /**
     * Set directory that contains HTTP responses.
     */
    public function responses($dir)
    {
        if (!is_dir($dir)) {
            throw new \InvalidArgumentException;
        }

        $this->responses = $dir;
    }

    /**
     * Set ciphers to be used by server.
     */
    public function ciphers($ciphers)
    {
        $this->ciphers = is_array($ciphers) ? implode(':', $ciphers) : $ciphers;

        return $this;
    }

    public function start()
    {
        $builder = new ProcessBuilder;

        // Prefix with exec to get rid of the spawning shell.
        $builder->setPrefix(array('exec', 'openssl', 's_server'));
        $builder = $this->buildCommand($builder);
        $builder->setTimeout(null);

        $this->process = $builder->getProcess();
        $this->process->start();

        // Give process a chance to start.
        usleep(10000);

        $i = 200;

        while (!$this->process->isRunning() && !$this->process->isTerminated() && --$i) {
            // I guess we wait...
            usleep(100);
        }

        if ($this->process->isTerminated()) {
            throw new \Exception(sprintf(
                "Process exited unexpectedly with %d[%s]\n\n%s\n\n%s",
                $this->process->getExitCode(),
                $this->process->getExitCodeText(),
                $this->process->getCommandLine(),
                $this->process->getErrorOutput()
            ));
        }

        if (!$this->process->isRunning()) {
            $this->process->stop(0); // Just in case.

            throw new \Exception;
        }

        return "https://{$this->host}:{$this->port}";
    }

    public function stop()
    {
        if ($this->process) {
            $this->process->stop(0);
        }
    }

    private function buildCommand(ProcessBuilder $builder)
    {
        if ($this->responses) {
            $builder->add('-HTTP');
            $builder->setWorkingDirectory($this->responses);
        } else {
            $builder->add('-www');
        }

        if ($this->ca && is_dir($this->ca)) {
            $builder->add('-CAdir')->add($this->ca);
        } elseif ($this->ca && is_file($this->ca)) {
            $builder->add('-CAfile')->add($this->ca);
        }

        $builder->add('-serverpref');
        $builder->add('-accept')->add((int) $this->port);
        $builder->add('-cert')->add($this->certificate);
        $builder->add('-key')->add($this->key);
        $builder->add('-cipher')->add($this->ciphers);

        return $builder;
    }
}
