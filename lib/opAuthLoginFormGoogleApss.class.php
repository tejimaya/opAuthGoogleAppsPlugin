<?php

/**
 * This file is part of the OpenPNE package.
 * (c) OpenPNE Project (http://www.openpne.jp/)
 *
 * For the full copyright and license information, please view the LICENSE
 * file and the NOTICE file that were distributed with this source code.
 */

/**
 * opAuthLoginFormOpenID represents a form to login by one's OpenID.
 *
 * @package    OpenPNE
 * @subpackage form
 * @author     Kousuke Ebihara <ebihara@tejimaya.com>
 * @author     Mamoru Tejima <tejima@tejimaya.com>
 */
class opAuthLoginFormGoogleApps extends opAuthLoginForm
{
  public function configure()
  {

    $hidden = new sfWidgetFormInputHidden();
    $_value = opConfig::get('op_auth_GoogleApps_plugin_googleapps_domain');
    if(null == $_value || "" == $_value){
      $_value = 'https://www.google.com/accounts/o8/id';
    }
    $hidden->setAttribute('value',$_value);
     
    $this->setWidget('openid_identifier', $hidden);
    $this->setValidator('openid_identifier', new sfValidatorString(array('required' => false)));
    $this->setValidator('openid', new sfValidatorString(array('required' => false)));

    $this->mergePostValidator(new sfValidatorCallback(array(
      'callback' => array($this, 'validate'),
      'arguments' => array(
        'realm' => $this->getAuthAdapter()->getCurrentUrl(),
        'return_to' => $this->getAuthAdapter()->getCurrentUrl(),
      ),
    )));

    parent::configure();
  }

  public function validate($validator, $values, $arguments = array())
  {
    if (!empty($values['openid']))
    {
      $validator = new opAuthValidatorMemberConfig(array('config_name' => 'openid'));
      $result = $validator->clean($values);
      return $result;
    }

    $result = $this->validateIdentifier($validator, $values, $arguments);
    return $result;
  }

  public function validateIdentifier($validator, $values, $arguments = array())
  {
    $authRequest = $this->getAuthAdapter()->getConsumer()->begin($values['openid_identifier']);
    if (!$authRequest)
    {
      throw new sfValidatorError($validator, 'Authentication error: not a valid OpenID.');
    }

    $sregExchange = new opOpenIDProfileExchange('sreg');
    $authRequest->addExtension(Auth_OpenID_SRegRequest::build(
      array(), $sregExchange->getImportSupportedProfiles()
    ));

    // for OpenID1
    if ($authRequest->shouldSendRedirect())
    {
      $values['redirect_url'] = $authRequest->redirectURL($arguments['realm'], $arguments['return_to']);
      if (Auth_OpenID::isFailure($values['redirect_url']))
      {
        throw new sfValidatorError($validator, 'Could not redirect to the server: '.$values['redirect_url']->message);
      }
    }
    // for OpenID2
    else
    {
      $axExchange = new opOpenIDProfileExchange('ax');

      $axRequest = new Auth_OpenID_AX_FetchRequest();
      $axRequest->add(Auth_OpenID_AX_AttrInfo::make('http://axschema.org/contact/email',2,1, 'email'));
      $axRequest->add(Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson/first',1,1, 'firstname'));
      $axRequest->add(Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson/last',1,1, 'lastname'));
      //error_log("for OpenID2\n");
      foreach ($axExchange->getImportSupportedProfiles() as $key => $value)
      {
        $axRequest->add(Auth_OpenID_AX_AttrInfo::make($value, 1, false, 'profile_'.$key));
      }
      $authRequest->addExtension($axRequest);

      $values['redirect_html'] = $authRequest->htmlMarkup($arguments['realm'], $arguments['return_to']);
      if (Auth_OpenID::isFailure($values['redirect_html']))
      {
        throw new sfValidatorError($validator, 'Could not redirect to the server: '.$values['redirect_html']->message);
      }
    }

    return $values;
  }

  public function getRedirectHtml()
  {
    return $this->getValue('redirect_html');
  }

  public function getRedirectUrl()
  {
    return $this->getValue('redirect_url');
  }
}
