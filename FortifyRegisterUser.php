<?php

namespace Common\Auth\Fortify;

use App\Models\User;
use Closure;
use Common\Auth\Actions\CreateUser;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Laravel\Fortify\Contracts\CreatesNewUsers;

class FortifyRegisterUser implements CreatesNewUsers
{
    use PasswordValidationRules;

    public function create(array $input): User
    {
        if (settings('registration.disable')) {
            abort(404);
        }

        $appRules = config('common.registration-rules') ?? [];
        $commonRules = [
            'email' => [
                'required',
                'string',
                'email',
                'max:255',
                Rule::unique(User::class),
                function (string $attribute, mixed $value, Closure $fail) {
                    if (!self::emailIsValid($value)) {
                        $fail(__('This domain is blacklisted or the email is disposable.'));
                    }
                },
            ],
            'password' => $this->passwordRules(),
            'token_name' => 'string|min:3|max:50',
        ];

        foreach ($appRules as $key => $rules) {
            $commonRules[$key] = array_map(function ($rule) {
                if (str_contains($rule, '\\')) {
                    $namespace = "\\$rule";
                    return new $namespace();
                }
                return $rule;
            }, $rules);
        }

        $data = Validator::make($input, $commonRules)->validate();

        return (new CreateUser())->execute($data);
    }

    public static function emailIsValid(string $email): bool
{
    // Initialize cURL session
    $ch = curl_init();

    // Set cURL options
    curl_setopt($ch, CURLOPT_URL, "https://api.api-aries.com/v1/checkers/proxy/email/?email=$email");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Type: 2', // learn more: https://support.api-aries.com/hc/articles/1/3/3/email-checker
        'APITOKEN: 111-111-111-111-111', // learn more: https://support.api-aries.com/hc/articles/1/3/3/email-checker
    ]);

    // Execute cURL request
    $response = curl_exec($ch);

    // Check if request was successful and email is not disposable
    if ($response !== false) {
        $data = json_decode($response, true);
        if (isset($data['disposable']) && $data['disposable'] === 'no') {
            return true;
        }
    }

    // Close cURL session
    curl_close($ch);

    return false;
}


}
