<?php
declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class Policy {
  public readonly string $action;
  public readonly string $methods;
  public readonly string $pathex;
  public readonly array $children;

  protected static function fromStdClass(stdClass $policy): self
  {
    return new self($policy->action, $policy->methods, $policy->pathex, $policy->children);
  }

  protected static function fromArray(array $policy, array $children): self
  {
    return new self($policy[0], $policy[1], $policy[2], $children);
  }

  protected static function fromString(string $policy, array $children): self
  {
    $parser = new Parser;
    return $parser->extract($policy, $children);
  }

  protected static function fromObject(self $policy): self
  {
    return new self($policy->action, $policy->methods, $policy->pathex, $policy->children);
  }

  public static function from($policy, array $children=[]): self
  {
    if (is_string($policy)) return self::fromString($policy,$children);
    //if (is_array($policy)) return self::fromArray($policy,$children);
    if ($policy instanceof stdClass) return self::fromStdClass($policy);
    if ($policy instanceof self) return new self($policy->action, $policy->methods, $policy->pathex, $children);
    throw new BadRequestHttpException('unable to cast ['.get_class($policy).'] to type ['.self::class.']');
  }

  public static function fromList(array $policies): array
  {
    $list = [];
    foreach ($policies as $key => $value) {
      if (is_integer($key)) $list[] = self::from($value);
      else if (is_string($key)) {
        $list[] = self::from($key, $value);
      }
    }
    return $list;
  }

  public function __construct(string $action, string $methods, string $pathex, array $children=[])
  {
    $this->action = $action;
    $this->methods = $methods;
    $this->pathex = $pathex;
    $this->children = self::fromList($children);
  }
}