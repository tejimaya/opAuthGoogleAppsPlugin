<?php

/**
 * This file is part of the OpenPNE package.
 * (c) OpenPNE Project (http://www.openpne.jp/)
 *
 * For the full copyright and license information, please view the LICENSE
 * file and the NOTICE file that were distributed with this source code.
 */

/**
 * opAuthAdapterGoogleApps will handle authentication for OpenPNE by OpenID
 *
 * @package    OpenPNE
 * @subpackage user
 * @author     Mamoru Tejima <tejima@tejimaya.com>
 */
class opAuthAdapterGoogleApps extends opAuthAdapter
{
  protected
    $authModuleName = 'GoogleApps',
    $consumer = null,
    $response = null;

  public function configure()
  {
    // for 3.4.x
    sfOpenPNEApplicationConfiguration::registerJanRainOpenID();

    require_once 'Auth/OpenID/SReg.php';
    require_once 'Auth/OpenID/AX.php';
    require_once 'google_discovery.php';
  }

  public function getConsumer()
  {
    if (!$this->consumer)
    {
      $this->consumer = new Auth_OpenID_Consumer(new Auth_OpenID_FileStore(sfConfig::get('sf_cache_dir')));
    }

    return $this->consumer;
  }

  public function getResponse()
  {
    if (!$this->response)
    {
      $response = $this->getConsumer()->complete($this->getCurrentUrl());
      if ($response->status === Auth_OpenID_SUCCESS)
      {
        $this->response = $response;
      }
    }

    return $this->response;
  }

  public function getAuthParameters()
  {
    $params = parent::getAuthParameters();
    $openid = null;

    if (sfContext::getInstance()->getRequest()->hasParameter('openid_mode'))
    {
      if ($this->getResponse())
      {
        $openid = $this->getResponse()->getDisplayIdentifier();
      }
    }

    $params['openid'] = $openid;

    return $params;
  }

  public function authenticate()
  {
    $result = parent::authenticate();

    if ($this->getAuthForm()->getRedirectHtml())
    {
      // We got a valid HTML contains JavaScript to redirect to the OpenID provider's site.
      // This HTML must not include any contents from symfony, so this script will stop here.
      echo $this->getAuthForm()->getRedirectHtml();
      exit;
    }
    elseif ($this->getAuthForm()->getRedirectUrl())
    {
      header('Location: '.$this->getAuthForm()->getRedirectUrl());
      exit;
    }

    $ax = Auth_OpenID_AX_FetchResponse::fromSuccessResponse($this->getResponse());
    if ($ax)
    {
      $email = $ax->data['http://axschema.org/contact/email'][0];

      if (!$this->isAllowedDomainAccount($email))
      {
        sfContext::getInstance()->getEventDispatcher()->notify(
          new sfEvent($this, 'application.log', array('not allowed domain'))
        );
        return false;
      }

      $memberConfig = Doctrine::getTable('MemberConfig')->retrieveByNameAndValue('pc_address', $email);

      $openid = $this->getAuthForm()->getValue('openid');
      if (!$result && $openid)
      {
        if ($memberConfig)
        {
          // for Backward Compatibility for this plugin
          $result = $memberConfig->getMemberId();
          Doctrine::getTable('MemberConfig')->setValue($result, 'openid', $openid);
        }
        else
        {
          $member = new Member();
          $member->setName("tmp");
          $member->setIsActive(true);
          $member->save();
          $member->setConfig('openid', $openid);
          $result = $member->getId();
        }
      }
    }

    $member = Doctrine::getTable('Member')->find($result);

    if ($ax)
    {
      $axExchange = new opOpenIDProfileExchange('ax', $member);
      $axExchange->setData($ax->data);

      $name .= $ax->data['http://axschema.org/namePerson/last'][0];
      $name .= $ax->data['http://axschema.org/namePerson/first'][0];
      $member->setName($name);

      // this code trust supplied email from google
      $member->setConfig('pc_address', $email);
    }
    $member->save();

    return $result;
  }

  public function getCurrentUrl()
  {
    return sfContext::getInstance()->getRequest()->getUri();
  }

  public function registerData($memberId, $form)
  {
    $member = Doctrine::getTable('Member')->find($memberId);
    if (!$member)
    {
      return false;
    }

    $member->setIsActive(true);

    return $member->save();
  }

  public function isRegisterBegin($memberId = null)
  {
    opActivateBehavior::disable();
    $member = Doctrine::getTable('Member')->find((int)$memberId);
    opActivateBehavior::enable();

    if (!$member || $member->getIsActive())
    {
      return false;
    }

    return true;
  }

  public function isRegisterFinish($memberId = null)
  {
    return false;
  }

  private function isAllowedDomainAccount($email)
  {
    $sp = preg_split('/@/', $email);
    if (2 !== count($sp))
    {
      return false;
    }
    $domains = explode(',', opConfig::get('op_auth_GoogleApps_plugin_googleapps_domain', ''));

    return false !== array_search($sp[1], $domains);
  }
}
