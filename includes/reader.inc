<?php

function isSigned(string $filePath): ?bool {
  if (file_exists($filePath)) {
    $pdfFileContent = file_get_contents(
      $filePath
    ); // Считываем содержимое PDF-файла
    $matchResult = preg_match(
      '/ByteRange.*Contents<[^>]+>/is',
      $pdfFileContent,
      $matches
    ); // Ищем определённую последовательность символов
    if ($matchResult === 1) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }
  else {
    return NULL;
  }
}

function getSignatureInfo(string $filePath): ?array {
  if (file_exists($filePath)) {
    $pdfFileContent = file_get_contents(
      $filePath
    ); // Считываем содержимое PDF-файла
    $matchResult = preg_match(
      '/ByteRange.*Contents<[^>]+>/is',
      $pdfFileContent,
      $matches
    ); // Ищем определённую последовательность символов
    if ($matchResult === 1) {
      $matchResult = preg_match(
        '/(?<=Contents<)[^>]+(?=>)/is',
        $matches[0],
        $matches
      ); // Очищаем от ненужного
      if ($matchResult === 1) {
        $drupalTempDirectoryName = file_directory_temp();
        $tempDirPath = "{$_SERVER['DOCUMENT_ROOT']}/{$drupalTempDirectoryName}/electronic_signature_reader";
        if (!file_exists($tempDirPath)) {
          mkdir($tempDirPath); // Создаём временную папку
        }
        $signatureFilePath = $tempDirPath . '/' . str_replace(
            ['.', ' '],
            '',
            microtime()
          ) . '.dat'; // Временный файл
        file_put_contents($signatureFilePath, hex2bin($matches[0]));
        $certs = shell_exec(
          "openssl pkcs7 -in {$signatureFilePath} -inform DER -print_certs"
        ); // Расшифровываем данные электронной подписи
        unlink($signatureFilePath); // Удаляем временный файл

        // Ищем данные сертификата в полученном результате >>>
        $certificateData = '';
        $matchResult = preg_match(
          '/-----BEGIN CERTIFICATE-----.+-----END CERTIFICATE-----/is',
          $certs,
          $matches
        );
        if ($matchResult === 1) {
          $signatureFilePath = $tempDirPath . '/' . str_replace(
              ['.', ' '],
              '',
              microtime()
            ) . '.dat';
          file_put_contents($signatureFilePath, $matches[0]);
          $certificateData = shell_exec(
            "openssl x509 -in {$signatureFilePath} -text -noout"
          );

          unlink($signatureFilePath);
        }
        else {
          return NULL;
        }
        // <<< Ищем данные сертификата в полученном результате

        // Расшифровываем сертификат из электронной подписи и получаем информационные данные для вывода на сайте >>>
        // Серийный номер, строка "Serial Number:"
        $serial = '';
        $matchResult = preg_match(
          '/^\s*Serial Number:.+$/m',
          $certificateData,
          $matches
        );
        if ($matchResult !== 1) {
          $certificateDataPruned = preg_replace(
            '/^.+(?=Serial Number:)/is',
            '',
            $certificateData
          );
          $certificateDataPrunedStrings = explode("\n", $certificateDataPruned);
          $serial = str_replace(':', '', $certificateDataPrunedStrings[1]);
          $serial = trim($serial);
          $matchResult = preg_match('/^[0-9a-f]$/i', $serial, $matches);
        }
        if ($matchResult === 1) {
          $serial = trim($matches[0]);
          $serial = str_replace('Serial Number:', '', $serial);
          $serial = str_replace(':', '', $serial);
          $serial = trim($serial);
        }

        // Полезные данные из строки "Subject:":
        // CN - Имя директора
        // O - Название учреждения
        // title - Должность
        $subjectCn = '';
        $subjectO = '';
        $subjectTitle = '';
        $matchResult = preg_match(
          '/^\s*Subject:.+$/m',
          $certificateData,
          $matches
        );
        if ($matchResult !== 1) {
          $certificateDataPruned = preg_replace(
            '/^.+(?=Subject:)/is',
            '',
            $certificateData
          );
          $certificateDataPrunedStrings = explode("\n", $certificateDataPruned);
          $subject = str_replace(':', '', $certificateDataPrunedStrings[1]);
          $subject = trim($subject);
          $matchResult = preg_match('/CN =/i', $subject, $matches);
          if ($matchResult === 1) {
            $matches[0] = $subject;
          }
        }
        if ($matchResult === 1) {
          $subject = trim($matches[0]);
          $subject = str_replace('Subject:', '', $subject);
          $subject = str_replace('\\', '%', $subject);
          $subject = urldecode($subject);

          // CN - Имя директора
          $matchResult = preg_match('/CN = [^,]+,/is', $subject, $matches);
          if ($matchResult !== 1) {
            $matchResult = preg_match('/CN = [^,]+$/is', $subject, $matches);
          }
          if ($matchResult === 1) {
            $subjectCn = str_replace(['CN =', ',', '%'], '', $matches[0]);
            $subjectCn = trim($subjectCn);
          }

          // O - Название учреждения
          $matchResult = preg_match('/O = [^,]+,/is', $subject, $matches);
          if ($matchResult !== 1) {
            $matchResult = preg_match('/O = [^,]+$/is', $subject, $matches);
          }
          if ($matchResult === 1) {
            $subjectO = str_replace(['O =', ',', '%'], '', $matches[0]);
            $subjectO = trim($subjectO);
          }

          // title - Должность
          $matchResult = preg_match('/title = [^,]+,/is', $subject, $matches);
          if ($matchResult !== 1) {
            $matchResult = preg_match('/title = [^,]+$/is', $subject, $matches);
          }
          if ($matchResult === 1) {
            $subjectTitle = str_replace(['title =', ',', '%'], '', $matches[0]);
            $subjectTitle = trim($subjectTitle);
          }
        }

        $arResult = [];
        if (!empty($serial)) {
          $arResult['serial'] = $serial;
        }
        if (!empty($subjectTitle)) {
          $arResult['title'] = $subjectTitle;
        }
        if (!empty($subjectO)) {
          $arResult['o'] = $subjectO;
        }
        if (!empty($subjectCn)) {
          $arResult['cn'] = $subjectCn;
        }

        if (!empty($arResult)) {
          return $arResult;
        }
        else {
          return NULL;
        }
        // <<< Расшифровываем сертификат из электронной подписи и получаем информационные данные для вывода на сайте
      }
      else {
        return NULL;
      }
    }
    else {
      return NULL;
    }
  }
  else {
    return NULL;
  }
}