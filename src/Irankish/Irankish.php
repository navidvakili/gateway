<?php

namespace Larabookir\Gateway\Irankish;

use Carbon\Carbon;
use DateTime;
use Exception;
use Illuminate\Support\Facades\Request;
use Larabookir\Gateway\Enum;
use SoapClient;
use Larabookir\Gateway\PortAbstract;
use Larabookir\Gateway\PortInterface;

class Irankish extends PortAbstract implements PortInterface
{
    /**
     * Address of main SOAP server
     *
     * @var string
     */
    protected $serverUrl = 'https://ikc.shaparak.ir/api/v3/tokenization/make';
    protected $serverVerifyUrl = "https://ikc.shaparak.ir/api/v3/confirmation/purchase";
    //    protected $serverVerifyUrl = "http://banktest.ir/gateway/irankishVerify/ws?wsdl";

    //    protected $gateUrl = "http://banktest.ir/gateway/irankish/gate";
    protected $gateUrl = "https://ikc.shaparak.ir/iuiv3/IPG/Index/";

    /**
     * {@inheritdoc}
     */
    public function set($amount)
    {
        $this->amount = $amount;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function ready()
    {
        $this->sendPayRequest();

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function redirect()
    {
        $gateUrl     = $this->gateUrl;
        $token      = $this->refId;
        // $merchantId = $this->config->get('gateway.irankish.merchantId');
        $PassPhrase = $this->config->get('gateway.irankish.PassPhrase');

        return view('gateway::irankish-redirector')->with(compact('token', 'gateUrl'));
    }

    /**
     * {@inheritdoc}
     */
    public function verify($transaction)
    {
        parent::verify($transaction);

        $this->userPayment();
        $this->verifyPayment();
        return $this;
    }

    /**
     * Sets callback url
     *
     * @param $url
     */
    function setCallback($url)
    {
        $this->callbackUrl = $url;

        return $this;
    }

    /**
     * Gets callback url
     * @return string
     */
    function getCallback()
    {
        if (!$this->callbackUrl) {
            $this->callbackUrl = $this->config->get('gateway.irankish.callback-url');
        }

        return $this->makeCallback($this->callbackUrl, ['transaction_id' => $this->transactionId()]);
    }

    protected function generateAuthenticationEnvelope($pub_key, $terminalID, $password, $amount)
    {
        $data = $terminalID . $password . str_pad($amount, 12, '0', STR_PAD_LEFT) . '00';
        $data = hex2bin($data);
        $AESSecretKey = openssl_random_pseudo_bytes(16);
        $ivlen = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        $iv = openssl_random_pseudo_bytes($ivlen);
        $ciphertext_raw = openssl_encrypt($data, $cipher, $AESSecretKey, $options = OPENSSL_RAW_DATA, $iv);
        $hmac = hash('sha256', $ciphertext_raw, true);
        $crypttext = '';

        openssl_public_encrypt($AESSecretKey . $hmac, $crypttext, $pub_key);

        return [
            "data" => bin2hex($crypttext),
            "iv" => bin2hex($iv),
        ];
    }

    /**
     * Send pay request to server
     *
     * @return void
     *
     * @throws IranKishException
     */
    protected function sendPayRequest()
    {
        $dateTime = new DateTime();

        $this->newTransaction();

        $token = $this->generateAuthenticationEnvelope(
            $this->config->get('gateway.irankish.pubkey'),
            $this->config->get('gateway.irankish.terminalID'),
            $this->config->get('gateway.irankish.password'),
            $this->amount
        );

        $data = [];
        $data["request"] = [
            "acceptorId" => $this->config->get('gateway.irankish.acceptorId'),
            "amount" => $this->amount,
            "billInfo" => null,

            "paymentId" => null,
            "requestId" => uniqid(),
            "requestTimestamp" => time(),
            "revertUri" => $this->getCallback(),
            "terminalId" => $this->config->get('gateway.irankish.terminalID'),
            "transactionType" => "Purchase",
            'authenticationEnvelope' => $token
        ];
        $data['authenticationEnvelope'] = $token;
        $data_string = json_encode($data);

        try {
            $ch = curl_init('https://ikc.shaparak.ir/api/v3/tokenization/make');
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'Content-Type: application/json',
                'Content-Length: ' . strlen($data_string)
            ));
            $result = curl_exec($ch);
            curl_close($ch);

            $response = json_decode($result, JSON_OBJECT_AS_ARRAY);

            if ($response["responseCode"] != "00") {
                $this->transactionFailed();
                $this->newLog($response["responseCode"], $response["description"]);
                throw new IranKishException($response["responseCode"]);
            }
        } catch (Exception $e) {
            $this->transactionFailed();
            $this->newLog('SoapFault', $e->getMessage());
            throw $e;
        }

        $this->refId = $response['result']['token'];
        $this->transactionSetRefId();
    }

    /**
     * Check user payment
     *
     * @return bool
     *
     * @throws IranKishException
     */
    protected function userPayment()
    {
        $this->refId        = Request::input('token');
        $this->trackingCode = Request::input('retrievalReferenceNumber');
        if (Request::has('maskedPan'))
            $this->cardNumber   = Request::input('maskedPan');
        $payRequestResCode  = Request::input('responseCode');

        if ($payRequestResCode == '00') {
            return true;
        }

        $this->transactionFailed();
        $this->newLog($payRequestResCode, @IrankishException::$errors[$payRequestResCode]);
        throw new IrankishException($payRequestResCode);
    }

    /**
     * Verify user payment from bank server
     *
     * @return bool
     *
     * @throws IranKishException
     * @throws SoapFault
     */
    protected function verifyPayment()
    {
        $fields = [
            "terminalId" => $this->config->get('gateway.irankish.terminalID'),
            "retrievalReferenceNumber" => $this->trackingCode(),
            "systemTraceAuditNumber" => Request::input('systemTraceAuditNumber'),
            "tokenIdentity" => $this->refId(),
        ];


        $data_string = json_encode($fields);


        try {
            $ch = curl_init('https://ikc.shaparak.ir/api/v3/confirmation/purchase');
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'Content-Type: application/json',
                'Content-Length: ' . strlen($data_string)
            ));

            $result = curl_exec($ch);
            if ($result === false) {
                $this->transactionFailed();
                $this->newLog(curl_error($ch), IrankishException::$errors[1]);
                throw new IrankishException(1);
            }
            curl_close($ch);

            $response = json_decode($result, JSON_OBJECT_AS_ARRAY);
        } catch (\SoapFault $e) {
            $this->transactionFailed();
            $this->newLog('SoapFault', $e->getMessage());
            throw $e;
        }

        if ($response['result']['amount']  != $this->amount) {
            $this->transactionFailed();
            $this->newLog($response['responseCode'], IrankishException::$errors[$response['responseCode']]);
            throw new IrankishException($response['responseCode']);
        }

        $this->transactionSucceed();
        $this->newLog($response['responseCode'], Enum::TRANSACTION_SUCCEED_TEXT);


        return true;
    }
}
