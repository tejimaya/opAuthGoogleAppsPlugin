<?php

/**
 * This file is part of the OpenPNE package.
 * (c) OpenPNE Project (http://www.openpne.jp/)
 *
 * For the full copyright and license information, please view the LICENSE
 * file and the NOTICE file that were distributed with this source code.
 */

/**
 * opAuthAdapterOpenID will handle authentication for OpenPNE by OpenID
 *
 * @package    OpenPNE
 * @subpackage user
 * @author     Kousuke Ebihara <ebihara@tejimaya.com>
 */
class opAuthAdapterGoogleApps extends opAuthAdapter
{
  protected
    $authModuleName = 'GoogleApps',
    $consumer = null,
    $response = null;

  public function configure()
  {
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
      $helper = new GApps_OpenID_Discovery($this->consumer);
      
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

    if ($this->getAuthForm()->isValid()
      && $this->getAuthForm()->getValue('openid')
      && !$this->getAuthForm()->getMember())
    {
      //$member = Doctrine::getTable('Member')->createPre();
      $member = new Member();
      $member->setName('MUDAMUDA');
      $member->setIsActive(true);
      $member->save();

      $member->setConfig('openid', $this->getAuthForm()->getValue('openid'));
      $this->appendMemberInformationFromProvider($member);
      $member->setName('ORAORA');

      $member->save();

      $result = $member->getId();
    }

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

  public function isRegisterBegin($member_id = null)
  {
    opActivateBehavior::disable();
    $member = Doctrine::getTable('Member')->find((int)$member_id);
    opActivateBehavior::enable();

    if (!$member || $member->getIsActive())
    {
      return false;
    }

    return true;
  }

  public function isRegisterFinish($member_id = null)
  {
    return false;
  }

  protected function appendMemberInformationFromProvider($member)
  {
    $ax = Auth_OpenID_AX_FetchResponse::fromSuccessResponse($this->getResponse());
    if ($ax)
    {
      $axExchange = new opOpenIDProfileExchange('ax', $member);
      $axExchange->setData($ax->data);
    }

    $sreg = Auth_OpenID_SRegResponse::fromSuccessResponse($this->getResponse());
    if ($sreg)
    {
      $sregExchange = new opOpenIDProfileExchange('sreg', $member);
      $sregExchange->setData($sreg->contents());
    }

    return $member;
  }
}
