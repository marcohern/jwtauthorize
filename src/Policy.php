<?php
declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Illuminate\Support\Collection;

class Policy {
  public readonly string $action;
  public readonly string $methods;
  public readonly string $pathex;
  public readonly Collection $children;

  private static Parser|null $parser = null;

  private static function getParser()
  {
    return self::$parser ??= new Parser;
  }

  protected static function fromStdClass(\stdClass $policy): self
  {
    $children = [];
    if (isset($policy->children)) $children = $policy->children;
    return new self($policy->action, $policy->methods, $policy->pathex, $children);
  }

  protected static function fromArray(array $policy, Collection|array $children): self
  {
    return new self($policy[0], $policy[1], $policy[2], $children);
  }

  protected static function fromString(string $policy, Collection|array $children): self
  {
    $parser = self::getParser();
    return $parser->extract($policy, $children);
  }

  protected static function fromObject(self $policy): self
  {
    return new self($policy->action, $policy->methods, $policy->pathex, $policy->children);
  }

  public static function from($policy, Collection|array $children=[]): self
  {
    if ($policy instanceof self) return $policy;
    if ($policy instanceof \stdClass) return self::fromStdClass($policy);
    if (is_string($policy)) return self::fromString($policy,$children);
    throw new BadRequestHttpException('unable to cast ['.get_class($policy).'] to type ['.self::class.']');
  }

  public static function fromList(Collection|array $policies): Collection
  {
    $list = [];
    foreach ($policies as $key => $value) {
      if (is_integer($key)) $list[] = self::from($value);
      else if (is_string($key)) {
        $list[] = self::from($key, $value);
      }
    }
    return collect($list);
  }

  public function __construct(string $action, string $methods, string $pathex, Collection|array $children=[])
  {
    $this->action = $action;
    $this->methods = $methods;
    $this->pathex = $pathex;
    $this->children = self::fromList($children);
  }
}