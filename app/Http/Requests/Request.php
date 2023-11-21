<?php

namespace App\Http\Requests;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;

class Request extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    protected function failedValidation(Validator $validator)
    {
        throw new HttpResponseException(response()->json([
            'errors' => $validator->errors(),
        ], 422));
    }

    public function withValidator($validator)
    {
        $validator->after(function ($validator) {
            $allowableFields = array_merge($this->rules(), ['page' => 'number', 'per_page' => 'number', 'order_by' => 'string', 'order_direction' => 'in:asc,desc', 'include' => 'string', 'detailed' => 'string', 'propertyId' => 'number']);

            foreach ($this->all() as $key => $value) {
                if (!array_key_exists($key, $allowableFields)) {

                    // if it is a IndexRequest return invalid filter message
                    if (strpos(get_called_class(), 'IndexRequest') !== false) {
                        $validator->errors()->add($key, 'Invalid filter.');
                    } else {
                        $validator->errors()->add($key, "Field does not exist.");
                    }
                }
            }
        });
    }
}
