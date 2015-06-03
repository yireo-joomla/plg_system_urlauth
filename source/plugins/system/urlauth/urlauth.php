<?php
/**
 * Joomla! System plugin - URL Authentication
 *
 * @author    Yireo (info@yireo.com)
 * @copyright Copyright 2015 Yireo.com. All rights reserved
 * @license   GNU Public License
 * @link      http://www.yireo.com
 */

// no direct access
defined('_JEXEC') or die('Restricted access');

// Import parent library
jimport('joomla.plugin.plugin');

/**
 * URL Authentication System Plugin
 *
 */
class plgSystemUrlAuth extends JPlugin
{
	protected $app;

	/**
	 * Catch the event onAfterInitialise
	 *
	 * @access public
	 * @param null
	 * @return null
	 */
	public function onAfterInitialise()
	{
		// Load system variables
		$user = JFactory::getUser();

		// Some stuff for Joomla! 3.2 and later
		$this->app->rememberCookieLifetime = time() + (24 * 60 * 60);
		$this->app->rememberCookieSecure = 1;
		$this->app->rememberCookieLength = 16;

		// Only allow usage from within the frontend
		if ($this->app->getName() != 'site')
		{
			return;
		}

		// Determine the variables for username and password
		$usernameVar = $this->params->get('username_var');
		$passwordVar = $this->params->get('password_var');

		if (empty($usernameVar))
		{
			$usernameVar = 'username';
		}

		if (empty($passwordVar))
		{
			$passwordVar = 'password';
		}

        // Fetch the redirect
        $redirect = $this->getRedirect();

		// Fetch the username and password from the request
		$username = $this->app->input->get($usernameVar);
		$password = $this->app->input->get($passwordVar);

		// If the credentials are empty, there's no point into using them
		if (empty($username) || empty($password))
		{
			return;
		}

		// If the current user is not a guest, authentication has already occurred
		if ($user->guest == 0)
		{
			$this->app->redirect($redirect);

			return;
		}

		// Restrict by IP
		if ($this->allowIp() == false)
		{
			$this->app->redirect($redirect);

			return;
		}

		// Authenticate
		if ((bool) $this->params->get('encrypt'))
		{
			$password = base64_decode($password);
			$rt = $this->doEncryptedLogin($username, $password);
		}
		else
		{
			$rt = $this->doLogin($username, $password, $redirect);
		}

		// Do not continue if login fails
		if ($rt == false)
		{
			return;
		}

		// Act on authentication success
		$this->app->setUserState('rememberLogin', false);
		$this->app->setUserState('users.login.form.data', array());

		// Redirect if needed
		if (!empty($redirect))
		{
			$this->app->redirect($redirect);

			return;
		}
	}

	/**
	 * Helper method to login using the regular Joomla Framework
	 *
	 * @access private
	 * @param string $username
	 * @param string $password
	 * @param string $redirect
	 *
	 * @return boolean
	 */
	private function doLogin($username, $password, $redirect = null)
	{
		// Construct the options for authentication
		$options = array();
		$options['remember'] = true;
		$options['return'] = $redirect;

		// Construct the credentials based on request parameters
		$credentials = array();
		$credentials['username'] = $username;
		$credentials['password'] = $password;
		$credentials['secretkey'] = '';

		// Try to login
		$rt = $this->app->login($credentials, $options);

		// Detect authentication failures
		if ($rt != true || JError::isError($rt))
		{
			$this->app->enqueueMessage(JText::_('PLG_SYSTEM_URLAUTH_ERROR_AUTHENTICATION_FAILED'), 'warning');
			return false;
		}

		return true;
	}

	/**
	 * Helper method to login using an encrypted password
	 *
	 * @access private
	 * @param string $username
	 * @param string $password
	 *
	 * @return boolean
	 */
	private function doEncryptedLogin($username, $password)
	{
		$app = JFactory::getApplication();
		$db = JFactory::getDBO();
		$query = $db->getQuery(true);

		$query->select($db->quoteName(array('id', 'username', 'password')))
			->from($db->quoteName('#__users'))
			->where($db->quoteName('username') . '=' . $db->quote($username))
			->where($db->quoteName('password') . '=' . $db->quote($password));

		$db->setQuery($query);
		$result = $db->loadObject();

		if (!$result)
		{
			$this->app->enqueueMessage(JText::_('PLG_SYSTEM_URLAUTH_ERROR_AUTHENTICATION_FAILED'), 'warning');
			return false;
		}

		JPluginHelper::importPlugin('user');

		$options = array();
		$options['action'] = 'core.login.site';

		$response['username'] = $result->username;

		$this->app->triggerEvent('onUserLogin', array((array)$response, $options));

		return true;
	}

	/**
	 * Helper method to implement IP checks
	 *
	 * @access public
	 *
	 * @return boolean
	 */
	private function allowIp()
	{
		$remoteIp = $_SERVER['REMOTE_ADDR'];

		// Include IP-addresses
		$include_ip = trim($this->params->get('include_ip'));

		if (!empty($include_ip))
		{
			$include_ips = explode(',', $include_ip);
			$match = false;

			foreach ($include_ips as $include_ip)
			{
				if ($remoteIp == trim($include_ip))
				{
					$match = true;
					break;
				}
			}

			// There is no match, so skip authentication
			if ($match == false)
			{
				return false;
			}
		}

		// Exclude IP-addresses
		$exclude_ip = trim($this->params->get('exclude_ip'));

		if (!empty($exclude_ip))
		{
			$exclude_ips = explode(',', $exclude_ip);

			foreach ($exclude_ips as $exclude_ip)
			{
				if ($remoteIp == trim($exclude_ip))
				{
					return false;
				}
			}
		}

		return true;
	}

    private function getRedirect()
    {
		// Allow a page to redirect the user to
		$redirect = (int) $this->params->get('redirect');

		if ($redirect > 0)
		{
            $menu = JFactory::getApplication()->getMenu();
            $menuItem = $menu->getItem($redirect);

            if($menuItem)
            {
                $link = $menuItem->link.'&Itemid='.$menuItem->id;
                if(!empty($menuItem->language) && $menuItem->language != '*') {
                    $link .= '&lang='.$menuItem->language;
                }
		    	$redirect = JRoute::_($link, false);
            }
		}
		else
		{
			$redirect = JURI::current();
		}

        return $redirect;
    }
}
