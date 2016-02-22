/*
 * Copyright 2008 Web Cohesion
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.springframework.security.oauth2.provider.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Retry implementation for token services using random UUID values for the access token and refresh token values. The
 * main extension point for customizations is the {@link TokenEnhancer} which will be called after the access and
 * refresh tokens have been generated but before they are stored.
 * <p>
 * Persistence is delegated to a {@code TokenStore} implementation and customization of the access token to a
 * {@link TokenEnhancer}.
 * 
 * @author Ryan Heaton
 * @author Luke Taylor
 * @author Dave Syer
 * @author Ashley Doub
 */
public class RetryTokenServices extends DefaultTokenServices {
	private static final Log LOG = LogFactory.getLog(RetryTokenServices.class);

	@Override
	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
		OAuth2AccessToken oAuth2AccessToken = null;
		boolean retry;
		do {
			try {
				oAuth2AccessToken = super.createAccessToken(authentication);
				retry = false;
			} catch (DuplicateKeyException e) {
				LOG.info("Duplicate key exception caught, retrying");
				retry = true;
			}
		} while (retry);
		return oAuth2AccessToken;
	}
}
