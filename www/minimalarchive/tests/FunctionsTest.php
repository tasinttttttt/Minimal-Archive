<?php

use PHPUnit\Framework\TestCase;

final class FunctionsTest extends TestCase
{
    public function testPutSuccess(): void
    {
        $message = "Good input ✨!";

        $this->expectOutputString("<aside class=\"notice success\">" . htmlspecialchars($message) . "</aside>", put_success($message));
    }

    public function testPutError(): void
    {
        $message = "Bad input 😢 <a href=\"/link\">html</a>!";

        $this->expectOutputString("<aside class=\"notice error\">" . htmlspecialchars($message) . "</aside>", put_error($message));
    }

    public function testSanitizeFilename(): void
    {
        $windows_reserved = [
            'CON',
            'PRN',
            'AUX',
            'NUL',
            'COM1',
            'COM2',
            'COM3',
            'COM4',
            'COM5',
            'COM6',
            'COM7',
            'COM8',
            'COM9',
            'LPT1',
            'LPT2',
            'LPT3',
            'LPT4',
            'LPT5',
            'LPT6',
            'LPT7',
            'LPT8',
            'LPT9',
        ];
        $bad_middle = [
            'file:name',
            'file*name',
            'file?name',
            'file"name',
            'file<name',
            'file>name',
            'file|name',
            'file/name',
            'file\\name',
            'file(name)',
            'file&name',
            'file;name',
            "file'name"
        ];
        $bad_first_or_last = [
            'filename ',
            '$filename',
            'filename.',
        ];
        $ok_names = [
            'file.name',
            'file4name',
            'file name',
            '✨💥✨'
        ];
        foreach ($windows_reserved as $filename) {
            $this->assertSame("_$filename", sanitize_filename($filename));
        }
        foreach ($bad_middle as $filename) {
            $this->assertSame('file-name', sanitize_filename($filename));
        }
        foreach ($bad_first_or_last as $filename) {
            $this->assertSame('filename', sanitize_filename($filename));
        }
        foreach ($ok_names as $filename) {
            $this->assertSame($filename, sanitize_filename($filename));
        }
    }
}
