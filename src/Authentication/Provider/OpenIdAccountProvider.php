<?php
declare(strict_types=1);

namespace RZ\Roadiz\OpenId\Authentication\Provider;

use RZ\Roadiz\OpenId\User\OpenIdAccount;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class OpenIdAccountProvider implements UserProviderInterface
{
    /**
     * @inheritDoc
     */
    public function loadUserByUsername(string $username)
    {
        throw new \RuntimeException('Cannot load an OpenId account with its email.');
    }

    /**
     * @inheritDoc
     */
    public function refreshUser(UserInterface $user)
    {
        if ($user instanceof OpenIdAccount) {
            if ($user->getJwtToken()->isExpired(new \DateTime('now'))) {
                throw new UsernameNotFoundException('OpenId token has expired, please authenticate again…');
            }
            return $user;
        }

        throw new UnsupportedUserException();
    }

    /**
     * @inheritDoc
     */
    public function supportsClass(string $class)
    {
        return $class === OpenIdAccount::class;
    }
}
