<?php

/**
 * This file is part of the OpenPNE package.
 * (c) OpenPNE Project (http://www.openpne.jp/)
 *
 * For the full copyright and license information, please view the LICENSE
 * file and the NOTICE file that were distributed with this source code.
 */

/**
 * opAuthConfigFormOpenID represents a form to configuration.
 *
 * @package    OpenPNE
 * @subpackage form
 * @author     Kousuke Ebihara <ebihara@tejimaya.com>
 * @author     Mamoru Tejima <tejima@tejimaya.com>
 */
class opAuthConfigFormGoogleApps extends opAuthConfigForm
{
  public function setup()
  {
    parent::setup();

    $this->getWidgetSchema()->setHelp('googleapps_domain', '",(コンマ)"を用いて複数のドメインを指定できます');
  }
}
