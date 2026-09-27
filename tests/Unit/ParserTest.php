<?php

declare(strict_types=1);

use Marcohern\Jwtauthorize\Parser;
use Marcohern\Jwtauthorize\Exceptions\JwtaParserException;

beforeEach(function () {
    $this->parser = new Parser;
});

// Runs AFTER every test in this file
afterEach(function ()
{
  
});

it('[Parser::isValid] can detect valid authorization strings', function (string $policy) {
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

it('[Parser::isValid] can detect invalid authorization strings', function (string $policy) {
    //Test
    $isValid = $this->parser->isValid($policy);
    
    //Assert
    expect($isValid)->toBeFalse();
})->with([
  ['policy' => 'allow PURE /.*/'],
  ['policy' => 'allow GE /.*/'],
  ['policy' => 'allow GETT /.*/'],
]);

it('[Parser::extract] can extract components from valid authorization string', function (string $policy, array $components) {
    //Test
    $policy = $this->parser->extract($policy);

    //Assert
    expect($policy->action)->toBe($components[0]);
    expect($policy->methods)->toBe($components[1]);
    expect($policy->pathex)->toBe($components[2]);
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
    $policy = $this->parser->extract($policy);

})->throws(JwtaParserException::class,'Policy invalid.')->with([
  
  'allow *',
  'allow * ',
  'allow *     ',
  'allow GE /.*/',
  'allow GETT /.*/',
  'allow GET,POST,PULL /.*/', //PULL is not a valid method
  'allow *,GET /.*/', //methods *,GET is invalid
  'allow + /.*/', //+ instead of * is rejected
  'accept * /abc/', //accept is not a valid action
  'reject POST /edf/', //reject is not a valid action
  'allow PUST /ghj/',//PUST is not a valid method
]);

it('[Parser::extract] cannot extract components from authorization string that have an invalid regex as path', function (string $policy) {
    
    //Test
    $policy = $this->parser->extract($policy);

})->throws(JwtaParserException::class,'Path in policy invalid.')->with([
  'allow * /', // '/' is not a valid regex
  'allow * /a', // '/a' is not a valid regex
  'allow GET abc', // missing '/':'/abc/'
  'allow GET /(/', // open parenthesis but not closing
  'allow GET /[/', // open square brackets but not closing
  'allow GET /?/', // '?' is a reserved char
  'allow GET /*/', // '*' is a reserved char
  'allow GET /+/', // '+' is a reserved char
]);