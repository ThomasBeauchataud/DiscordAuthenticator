<?php

/*
 * Author Thomas Beauchataud
 * Since 22/05/2022
 */

namespace TBCD\DiscordAuthenticator\OAuth;

class DiscordOAuthResponse
{

    private string $id;
    private string $username;
    private string $token;
    private string $refreshToken;
    private int $validity;

    public function __construct(string $id, string $username, string $token, string $refreshToken, int $validity)
    {
        $this->id = $id;
        $this->username = $username;
        $this->token = $token;
        $this->refreshToken = $refreshToken;
        $this->validity = $validity;
    }


    /**
     * @return string
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * @return string
     */
    function getUsername(): string
    {
        return $this->username;
    }

    /**
     * @return string
     */
    function getToken(): string
    {
        return $this->token;
    }

    /**
     * @return string
     */
    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    /**
     * @return int
     */
    function getValidity(): int
    {
        return $this->validity;
    }

    /**
     * @return string
     */
    public function getUserIdentifier(): string
    {
        return $this->id;
    }
}