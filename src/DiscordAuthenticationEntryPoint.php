<?php

/*
 * The file is part of the WoWUltimate project 
 * 
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * Author Thomas Beauchataud
 * From 26/05/2022
 */

namespace TBCD\DiscordAuthenticator;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class DiscordAuthenticationEntryPoint implements AuthenticationEntryPointInterface

{
    private UrlGeneratorInterface $urlGenerator;
    private string $redirectRoute;
    private string $discordClient;

    public function __construct(UrlGeneratorInterface $urlGenerator, string $redirectRoute, string $discordClient)
    {
        $this->urlGenerator = $urlGenerator;
        $this->redirectRoute = $redirectRoute;
        $this->discordClient = $discordClient;
    }


    /**
     * @inheritDoc
     */
    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        $redirect = $this->urlGenerator->generate($this->redirectRoute);
        $client = $this->discordClient;
        return new RedirectResponse("https://discord.com/api/oauth2/authorize?client_id=$client&scope=identify&response_type=code&redirect_uri=$redirect&prompt=none");
    }
}