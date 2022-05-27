<?php

/*
 * Author Thomas Beauchataud
 * Since 22/05/2022
 */

namespace TBCD\DiscordAuthenticator\Authenticator;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use TBCD\DiscordAuthenticator\OAuth\DiscordOAuthClient;
use TBCD\DiscordAuthenticator\Token\DiscordToken;

class DiscordAuthenticator implements AuthenticatorInterface
{

    protected ?AuthenticationFailureHandlerInterface $authenticationFailureHandler;
    protected ?AuthenticationSuccessHandlerInterface $authenticationSuccessHandler;
    protected RouterInterface $router;
    protected DiscordOAuthClient $discordOAuthClient;
    protected string $redirectRoute;

    public function __construct(RouterInterface $router, DiscordOAuthClient $discordOAuthClient, string $redirectRoute, AuthenticationFailureHandlerInterface $authenticationFailureHandler = null, AuthenticationSuccessHandlerInterface $authenticationSuccessHandler = null)
    {
        $this->authenticationFailureHandler = $authenticationFailureHandler;
        $this->authenticationSuccessHandler = $authenticationSuccessHandler;
        $this->router = $router;
        $this->discordOAuthClient = $discordOAuthClient;
        $this->redirectRoute = $redirectRoute;
    }


    /**
     * @inheritDoc
     */
    public function supports(Request $request): bool
    {
        return $this->router->match($request->getPathInfo())['_route'] === $this->redirectRoute;
    }

    /**
     * @inheritDoc
     */
    public function authenticate(Request $request): Passport
    {
        if (!$request->query->has('code')) {
            throw new AuthenticationException();
        }

        try {
            $discordOAuthResponse = $this->discordOAuthClient->getCredentials($request->query->get('code'));
            $identifier = $discordOAuthResponse->getUserIdentifier();
        } catch (ExceptionInterface $e) {
            $message = 'Error while requesting Discord OAuth Api.';
            throw new AuthenticationException($message, 0, $e);
        }

        return new SelfValidatingPassport(new UserBadge($identifier));
    }

    /**
     * @inheritDoc
     */
    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        return new DiscordToken($passport->getUser(), $firewallName, $passport->getUser()->getRoles());
    }

    /**
     * @inheritDoc
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return $this->authenticationSuccessHandler?->onAuthenticationSuccess($request, $token);
    }

    /**
     * @inheritDoc
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return $this->authenticationFailureHandler?->onAuthenticationFailure($request, $exception);
    }
}