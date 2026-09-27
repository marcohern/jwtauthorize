<?php
declare(strict_types=1);

namespace Marcohern\Jwtauthorize;

use Illuminate\Support\Collection;

class Policy {
  public readonly string $action;
  public readonly string $methods;
  public readonly string $pathex;
  public readonly Collection $children;

  public function __construct(string $action, string $methods, string $pathex, Collection $children = new Collection)
  {
    $this->action = $action;
    $this->methods = $methods;
    $this->pathex = $pathex;
    $this->children = $children;
  }
}
