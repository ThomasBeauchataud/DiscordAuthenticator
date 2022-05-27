<?php

/*
 * Author Thomas Beauchataud
 * Since 22/05/2022
 */

namespace TBCD\DiscordAuthenticator\OAuth;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class DiscordOAuthClient
{

    public const ID_KEY = 'id';
    public const DISCRIMINATOR_KEY = 'discriminator';
    public const USERNAME_KEY = 'username';
    public const ACCESS_TOKEN_KEY = 'access_token';
    public const EXPIRATION_TOKEN_KEY = 'expires_in';
    public const REFRESH_TOKEN_KEY = 'refresh_token';

    private HttpClientInterface $httpClient;
    private UrlGeneratorInterface $urlGenerator;
    private string $redirectRoute;
    private string $discordClient;
    private string $discordSecret;

    public function __construct(HttpClientInterface $restClient, UrlGeneratorInterface $urlGenerator, string $redirectRoute, string $discordClient, string $discordSecret)
    {
        $this->httpClient = $restClient;
        $this->urlGenerator = $urlGenerator;
        $this->redirectRoute = $redirectRoute;
        $this->discordClient = $discordClient;
        $this->discordSecret = $discordSecret;
    }


    /**
     * @param string $authCode
     * @return DiscordOAuthResponse
     * @throws ExceptionInterface
     */
    public function getCredentials(string $authCode): DiscordOAuthResponse
    {
        $credentials = $this->getAccessToken($authCode);
        $userInfo = $this->getUserInfo($credentials[self::ACCESS_TOKEN_KEY]);
        return new DiscordOAuthResponse(
            $userInfo[self::ID_KEY],
            $userInfo[self::USERNAME_KEY] . '#' . $userInfo[self::DISCRIMINATOR_KEY],
            $credentials[self::ACCESS_TOKEN_KEY],
            $credentials[self::REFRESH_TOKEN_KEY],
            $credentials[self::EXPIRATION_TOKEN_KEY]
        );
    }

    /**
     * @param string $authCode
     * @return array
     * @throws ExceptionInterface
     */
    private function getAccessToken(string $authCode): array
    {
        $url = 'https://discord.com/api/oauth2/token';
        $payload = [
            'grant_type' => "authorization_code",
            'client_id' => $this->discordClient,
            'client_secret' => $this->discordSecret,
            'redirect_uri' => $this->urlGenerator->generate($this->redirectRoute, [], UrlGeneratorInterface::ABSOLUTE_URL),
            'code' => $authCode
        ];
        $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];
        $response = $this->httpClient->request(Request::METHOD_POST, $url, ['body' => $payload, 'headers' => $headers]);
        return $response->toArray();
    }

    /**
     * @param string $accessToken
     * @return array
     * @throws ExceptionInterface
     */
    private function getUserInfo(string $accessToken): array
    {
        $url = 'https://discord.com/api/users/@me';
        $headers = ["Authorization" => "Bearer $accessToken"];
        $response = $this->httpClient->request(Request::METHOD_GET, $url, ['headers' => $headers]);
        return $response->toArray();
    }
}