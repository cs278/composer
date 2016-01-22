<?php

namespace Composer\Test\Util\RemoteFilesystem;

use Composer\Util\RemoteFilesystem;
use Composer\Downloader\TransportException;

/**
 * @requires OS Linux|Darwin|.*BSD|.*Cygwin
 * @requires extension openssl
 */
class FunctionalTest extends \PHPUnit_Framework_TestCase
{
    public function testSelfSignedRejectTrust()
    {
        $server = TlsServer::createSelfSignedLocalhost();
        $url = $server->start();
        $rfs = $this->getRfs();

        try {
            $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array());
        } catch (TransportException $e) {
            $this->assertContains('certificate verify failed', $e->getMessage());

            return;
        }

        $this->fail();
    }

    public function testSelfSignedRejectCn()
    {
        $server = TlsServer::createSelfSignedGarbage();
        $url = $server->start();
        $rfs = $this->getRfs();

        try {
            $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array(
                'ssl' => array(
                    'allow_self_signed' => true,
                ),
            ));
        } catch (TransportException $e) {
            $this->assertContains('Peer certificate CN=`garbage\' did not match expected CN=`localhost\'', $e->getMessage());

            return;
        }

        $this->fail();
    }

    public function testSelfSignedAccept()
    {
        $server = TlsServer::createSelfSignedLocalhost();
        $url = $server->start();
        $rfs = $this->getRfs();

        $result = $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array(
            'ssl' => array(
                'allow_self_signed' => true,
            ),
        ));

        $this->assertContains('s_server', $result);

    }

    public function testSignedRejectTrust()
    {
        $server = TlsServer::createSignedLocalhost('i1-trusted', false);
        $url = $server->start();
        $rfs = $this->getRfs();

        try {
            $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array());
        } catch (TransportException $e) {
            $this->assertContains('certificate verify failed', $e->getMessage());

            return;
        }

        $this->fail();
    }

    public function testSignedRejectBrokenChain()
    {
        $server = TlsServer::createSignedLocalhost('i2-untrusted', false);
        $url = $server->start();
        $rfs = $this->getRfs();

        try {
            $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array(
                'ssl' => array(
                    'cafile' => __DIR__.'/ca/cafile.pem',
                ),
            ));
        } catch (TransportException $e) {
            $this->assertContains('certificate verify failed', $e->getMessage());

            return;
        }

        $this->fail();
    }

    public function testSignedAcceptTrustWithCaFileAndChain()
    {
        $server = TlsServer::createSignedLocalhost('i2-untrusted', true);
        $url = $server->start();
        $rfs = $this->getRfs();

        $result = $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array(
            'ssl' => array(
                'cafile' => __DIR__.'/ca/cafile.pem',
            ),
        ));

        $this->assertContains('s_server', $result);
    }

    public function testSignedAcceptTrustWithCaPathAndChain()
    {
        $server = TlsServer::createSignedLocalhost('i2-untrusted', true);
        $url = $server->start();
        $rfs = $this->getRfs();

        $result = $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array(
            'ssl' => array(
                'capath' => __DIR__.'/ca/cadir',
            ),
        ));

        $this->assertContains('s_server', $result);
    }

    public function testSignedAcceptTrustWithCaFile()
    {
        $server = TlsServer::createSignedLocalhost('i1-trusted', false);
        $url = $server->start();
        $rfs = $this->getRfs();

        $result = $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array(
            'ssl' => array(
                'cafile' => __DIR__.'/ca/cafile.pem',
            ),
        ));

        $this->assertContains('s_server', $result);
    }

    public function testSignedAcceptTrustWithCaPath()
    {
        $server = TlsServer::createSignedLocalhost('i1-trusted', false);
        $url = $server->start();
        $rfs = $this->getRfs();

        $result = $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array(
            'ssl' => array(
                'capath' => __DIR__.'/ca/cadir',
            ),
        ));

        $this->assertContains('s_server', $result);
    }

    /**
     * @requires internet
     */
    public function testSignedAcceptSanCertUsingCn()
    {
        $server = TlsServer::createSignedNipIo('', 'i1-trusted', false);
        $url = $server->start();
        $rfs = $this->getRfs();

        $result = $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array(
            'ssl' => array(
                'capath' => __DIR__.'/ca/cadir',
            ),
        ));

        $this->assertContains('s_server', $result);
    }

    /**
     * @requires internet
     */
    public function testSignedAcceptSanCertUsingAlt()
    {
        $server = TlsServer::createSignedNipIo('www', 'i1-trusted', false);
        $url = $server->start();
        $rfs = $this->getRfs();

        $result = $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array(
            'ssl' => array(
                'capath' => __DIR__.'/ca/cadir',
            ),
        ));

        $this->assertContains('s_server', $result);
    }

    /**
     * @requires internet
     */
    public function testSignedRejectSanCertUsingUnknownAlt()
    {
        $server = TlsServer::createSignedNipIo('www2', 'i1-trusted', false);
        $url = $server->start();
        $rfs = $this->getRfs();

        try {
            $rfs->getContents(parse_url($url, PHP_URL_HOST), $url, false, array(
                'ssl' => array(
                    'capath' => __DIR__.'/ca/cadir',
                ),
            ));
        } catch (TransportException $e) {
            $this->assertContains('Peer certificate CN=`127.0.0.1.nip.io\' did not match expected CN=`www2.127.0.0.1.nip.io\'', $e->getMessage());

            return;
        }

        $this->fail();
    }

    private function getRfs()
    {
        $io = $this->getIO();
        return new RemoteFilesystem($io);
    }

    private function getIO()
    {
        return $this->getMock('Composer\IO\IOInterface');
    }
}
