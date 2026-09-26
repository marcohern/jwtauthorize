<?php

declare(strict_types=1);


use Marcohern\Jwtauthorize\Parser;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

beforeEach(function () {
    $this->parser = new Parser;
});

// Runs AFTER every test in this file
afterEach(function ()
{
  
});

it('[Parser::isValid] can validate propper authorization string', function (string $policy) {
    //Test
    $isValid = $this->parser->isValid($policy);
    
    //Assert
    expect($isValid)->toBeTrue();
})->with([
  ['policy' => 'allow * /.*/'], //allow everything,
  ['policy' => 'allow GET,PUT,PATCH,POST,DELETE /.*/'], //allow everything explicitely
  ['policy' => 'deny * /\/admin(\/.*)?/'], //deny /admin or /admin/*
  ['policy' => 'allow * /\/entity(\/.*)?/'], //allow /entity or /entity/*
  ['policy' => 'deny POST /\/entity(\/.*)?/'], //deny POST /entity or /entity/*
]);

it('[Parser::extract] can extract components from valid authorization string', function (string $policy, array $components) {
    //Test
    list($action,$methods,$pathex) = $this->parser->extract($policy);

    //Assert
    expect($action)->toBe($components[0]);
    expect($methods)->toBe($components[1]);
    expect($pathex)->toBe($components[2]);
})->with([
  ['policy' => 'allow * /.*/', 'components' => ['allow','*','/.*/']], //allow everything,
  ['policy' => 'allow * //', 'components' => ['allow','*','//']], //allow empty,
  ['policy' => 'allow * /\//', 'components' => ['allow','*','/\//']], //allow all methods in home,
  ['policy' => 'allow * /abc/', 'components' => ['allow','*','/abc/']],
  ['policy' => 'allow GET,PUT,PATCH,POST,DELETE /.*/', 'components' => ['allow','GET,PUT,PATCH,POST,DELETE','/.*/']], //allow everything explicitely
  ['policy' => 'deny * /\/admin(\/.*)?/', 'components' => ['deny','*','/\/admin(\/.*)?/']], //deny /admin or /admin/*
  ['policy' => 'allow * /\/users(\/.*)?/', 'components' => ['allow','*','/\/users(\/.*)?/']], //allow /users or /users/*
  ['policy' => 'deny POST /\/orders(\/.*)?/', 'components' => ['deny','POST','/\/orders(\/.*)?/']], //deny POST /orders or /orders/*
  ]);

it('[Parser::extract] cannot extract components from invalid authorization string', function (string $policy) {
    
    //Test
    list($action,$methods,$pathex) = $this->parser->extract($policy);

})->throws(BadRequestHttpException::class,'Policy invalid.')->with([
  
  ['policy' => 'allow *'],
  ['policy' => 'allow * '],
  ['policy' => 'allow *     '],
  ['policy' => 'allow GET,POST,PULL /.*/'], //PULL is not a valid method
  ['policy' => 'allow *,GET /.*/'], //methods *,GET is invalid
  ['policy' => 'allow + /.*/'], //+ instead of * is rejected
  ['policy' => 'accept * /abc/'], //accept is not a valid action
  ['policy' => 'reject POST /edf/'], //reject is not a valid action
  ['policy' => 'allow PUST /ghj/'],//PUST is not a valid method
  
]);

it('[Parser::extract] cannot extract components from authorization string that have an invalid regex as path', function (string $policy) {
    
    //Test
    list($action,$methods,$pathex) = $this->parser->extract($policy);

})->throws(BadRequestHttpException::class,'Path in policy invalid.')->with([
  ['policy' => 'allow * /'], // '/' is not a valid regex
  ['policy' => 'allow * /a'], // '/a' is not a valid regex
  ['policy' => 'allow GET abc'], // missing '/':'/abc/'
  ['policy' => 'allow GET /(/'], // open parenthesis but not closing
  ['policy' => 'allow GET /[/'], // open square brackets but not closing
  ['policy' => 'allow GET /?/'], // '?' is a reserved char
  ['policy' => 'allow GET /*/'], // '*' is a reserved char
  ['policy' => 'allow GET /+/'], // '+' is a reserved char
]);