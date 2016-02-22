package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.Test;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.TokenRequest;

/**
 * @author Dave Syer
 * 
 */
public abstract class AbstractPersistentDefaultTokenServicesTests extends AbstractDefaultTokenServicesTests {

	@Test
	public void testTokenEnhancerUpdatesStoredTokens() throws Exception {
		final ExpiringOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken("testToken", new Date(
				System.currentTimeMillis() + 100000));
		getTokenServices().setTokenEnhancer(new TokenEnhancer() {
			public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
				DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
				result.setRefreshToken(refreshToken);
				return result;
			}
		});
		OAuth2Authentication authentication = createAuthentication();
		OAuth2AccessToken original = getTokenServices().createAccessToken(authentication);
		assertTrue(original.getRefreshToken().equals(refreshToken));
		OAuth2AccessToken result = getTokenStore().getAccessToken(authentication);
		assertEquals(original, result);
		assertEquals(refreshToken, result.getRefreshToken());
		assertEquals(refreshToken, getTokenStore().readRefreshToken(refreshToken.getValue()));
	}

	@Test
	public void testRefreshedTokenIsEnhanced() throws Exception {
		getTokenServices().setTokenEnhancer(new TokenEnhancer() {
			public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
				DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
				result.setValue("I'mEnhanced");
				return result;
			}
		});

		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
		assertTrue(accessToken.getValue().startsWith("I'mEnhanced"));
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				accessToken.getRefreshToken().getValue(), tokenRequest);
		assertTrue(refreshedAccessToken.getValue().startsWith("I'mEnhanced"));
	}

	@Test
	public void testOneAccessTokenPerAuthentication() throws Exception {
		OAuth2Authentication authentication = createAuthentication();
		OAuth2AccessToken first = getTokenServices().createAccessToken(authentication);
		assertEquals(1, getAccessTokenCount());
		assertEquals(1, getRefreshTokenCount());
		OAuth2AccessToken second = getTokenServices().createAccessToken(authentication);
		assertEquals(first, second);
		assertEquals(1, getAccessTokenCount());
		assertEquals(1, getRefreshTokenCount());
	}

	@Test
	public void testOneAccessTokenPerUniqueAuthentication() throws Exception {
		getTokenServices()
				.createAccessToken(
						new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false,
								Collections.singleton("read")), new TestAuthentication("test2",
								false)));
		assertEquals(1, getAccessTokenCount());
		getTokenServices()
				.createAccessToken(
						new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false,
								Collections.singleton("write")), new TestAuthentication(
								"test2", false)));
		assertEquals(2, getAccessTokenCount());
	}

	@Test
	public void testOneAccessTokenPerAuthenticationInMultipleRequests() throws InterruptedException, ExecutionException {
		Callable<OAuth2AccessToken> task = new Callable<OAuth2AccessToken>() {
			@Override
			public OAuth2AccessToken call() {
				OAuth2Authentication authentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false,
																														Collections.singleton("read,write")), new TestAuthentication("test2",
																																													 false));
				return getRetryTokenServices()
						.createAccessToken(
								authentication);
			}
		};
		int numberOfTasks = 75;
		List<Callable<OAuth2AccessToken>> tasks = Collections.nCopies(numberOfTasks, task);
		ExecutorService executorService = Executors.newFixedThreadPool(2);
		List<Future<OAuth2AccessToken>> futures = executorService.invokeAll(tasks);
		List<OAuth2AccessToken> resultList = new ArrayList<OAuth2AccessToken>(futures.size());
		for (Future<OAuth2AccessToken> future : futures) {
			resultList.add(future.get());
		}
		assertEquals(numberOfTasks, resultList.size());
		OAuth2AccessToken oAuth2AccessToken = resultList.get(0);
		for (OAuth2AccessToken token : resultList) {
			assertEquals(oAuth2AccessToken, token);
		}
	}

	@Test
	public void testRefreshTokenMaintainsState() throws Exception {
		getTokenServices().setSupportRefreshToken(true);
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
		OAuth2RefreshToken expectedExpiringRefreshToken = accessToken.getRefreshToken();
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue(), tokenRequest);
		assertNotNull(refreshedAccessToken);
		assertEquals(1, getAccessTokenCount());
	}

	@Test
	public void testNotReuseRefreshTokenMaintainsState() throws Exception {
		getTokenServices().setSupportRefreshToken(true);
		getTokenServices().setReuseRefreshToken(false);
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
		OAuth2RefreshToken expectedExpiringRefreshToken = accessToken.getRefreshToken();
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue(), tokenRequest);
		assertNotNull(refreshedAccessToken);
		assertEquals(1, getRefreshTokenCount());
	}

	protected abstract int getAccessTokenCount();

	protected abstract int getRefreshTokenCount();

}
