<?php

/*
 * This file is part of Twig.
 *
 * (c) Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Twig\Extension;

use Twig\NodeVisitor\SandboxNodeVisitor;
use Twig\Sandbox\SecurityPolicyInterface;
use Twig\TokenParser\SandboxTokenParser;

/**
 * @final
 */
class SandboxExtension extends AbstractExtension
{
    protected $sandboxedGlobally;
    protected $sandboxed;
    protected $policy;

    public function __construct(SecurityPolicyInterface $policy, $sandboxed = false)
    {
        $this->policy = $policy;
        $this->sandboxedGlobally = $sandboxed;
    }

    public function getTokenParsers()
    {
        return [new SandboxTokenParser()];
    }

    public function getNodeVisitors()
    {
        return [new SandboxNodeVisitor()];
    }

    public function enableSandbox()
    {
        $this->sandboxed = true;
    }

    public function disableSandbox()
    {
        $this->sandboxed = false;
    }

    public function isSandboxed()
    {
        return $this->sandboxedGlobally || $this->sandboxed;
    }

    public function isSandboxedGlobally()
    {
        return $this->sandboxedGlobally;
    }

    public function setSecurityPolicy(SecurityPolicyInterface $policy)
    {
        $this->policy = $policy;
    }

    public function getSecurityPolicy()
    {
        return $this->policy;
    }

    public function checkSecurity($tags, $filters, $functions)
    {
        if ($this->isSandboxed()) {
            $this->policy->checkSecurity($tags, $filters, $functions);
        }
    }

    public function checkMethodAllowed($obj, $method)
    {
        if ($this->isSandboxed()) {
            $this->policy->checkMethodAllowed($obj, $method);
        }
    }

    public function checkPropertyAllowed($obj, $method)
    {
        if ($this->isSandboxed()) {
            $this->policy->checkPropertyAllowed($obj, $method);
        }
    }

    public function ensureToStringAllowed($obj)
    {
        if (\is_array($obj)) {
            $this->ensureToStringAllowedForArray($obj);
            return $obj;
        }

        if ($this->isSandboxed() && \is_object($obj) && method_exists($obj, '__toString')) {
            $this->policy->checkMethodAllowed($obj, '__toString');
        }

        return $obj;
    }

    public function getName()
    {
        return 'sandbox';
    }

    private function ensureToStringAllowedForArray(array $obj): void
    {
        foreach ($obj as $k => $v) {
            if (!$v) {
                continue;
            }

            if (!\is_array($v)) {
                $this->ensureToStringAllowed($v);
                continue;
            }

            if (\PHP_VERSION_ID < 70400) {
                static $cookie;

                if ($v === $cookie ?? $cookie = new \stdClass()) {
                    continue;
                }

                $obj[$k] = $cookie;
                try {
                    $this->ensureToStringAllowedForArray($v);
                } finally {
                    $obj[$k] = $v;
                }

                continue;
            }

            if ($r = \ReflectionReference::fromArrayElement($obj, $k)) {
                if (isset($stack[$r->getId()])) {
                    continue;
                }

                $stack[$r->getId()] = true;
            }

            $this->ensureToStringAllowedForArray($v);
        }
    }
}

class_alias('Twig\Extension\SandboxExtension', 'Twig_Extension_Sandbox');
