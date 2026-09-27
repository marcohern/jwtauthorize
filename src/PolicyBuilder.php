<?php
declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Support\Collection;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class PolicyBuilder {
  public function __construct(public Parser $parser)
  {
  }

  protected function fromStdClass(\stdClass $policy): Policy
  {
    $children = $this->fromList($policy->children ?? []);
    return new Policy($policy->action, $policy->methods, $policy->pathex, $children);
  }

  protected function fromArray(array $policy, Collection|array $children): Policy
  {
    return new Policy($policy[0], $policy[1], $policy[2], $this->fromList($children));
  }

  protected function fromString(string $policy, Collection|array $children): Policy
  {
    return $this->parser->extract($policy, $this->fromList($children));
  }

  public function from($policy, Collection|array $children=[]): Policy
  {
    if ($policy instanceof Policy) return $policy;
    if ($policy instanceof \stdClass) return $this->fromStdClass($policy);
    if (is_string($policy)) return $this->fromString($policy,$children);
    throw new BadRequestHttpException('unable to cast ['.get_debug_type($policy).'] to type ['.Policy::class.']');
  }

  public function fromList(Collection|array $policies): Collection
  {
    $list = [];
    foreach ($policies as $key => $value) {
      if (is_integer($key)) $list[] = $this->from($value);
      else if (is_string($key)) {
        $list[] = $this->from($key, $value);
      }
    }
    return collect($list);
  }

}
