<?php

class Api
{
    private const ERROR_NO_IMAGE_FOLDER = 'no_image_folder';

    public function __construct(
        private string $imageFolder = DEFAULT_IMAGEFOLDER,
        private string $metaFile = DEFAULT_METAFILE
    ) {
    }

    /**
     * Upload operation handle
     */
    public function upload(array $files = []): void
    {
        try {
            $imagesdir = $this->imageFolder;
            if (!$imagesdir) {
                throw new \Exception(self::ERROR_NO_IMAGE_FOLDER, 1);
            }
            $data = [];
            foreach ($files as $file) {
                $filename = save_file($file, $file['name'], $this->imageFolder);
                $data[] = [
                    'name' => $filename,
                    'type' => $file['type'],
                    'extension' => pathinfo($file['name'], PATHINFO_EXTENSION)
                ];
            }
            json_response('ok', 200, $data);
        } catch (\Exception $e) {
            json_response($e->getMessage(), 400);
        }
    }

    /**
     * Save data to files
     */
    public function save(?array $data): void
    {
        if (!$data || !count($data)) {
            json_response('Bad query', 400);
            return;
        }
        try {
            $meta = textFileToArray($this->metaFile);
            $result = [];
            foreach ($data as $key => $value) {
                if ($key !== 'images' && !is_array($value)) {
                    if (array_key_exists($key, $meta)) {
                        $meta[$key] = trim($value);
                        $result[$key] = $meta[$key];
                    } else { // adding new entries
                        $meta[$key] = trim($value);
                        $result[$key] = $meta[$key];
                    }
                }
            }
            array_to_file($meta);
            if (array_key_exists('images', $data)) {
                $result['images'] = $this->delete_all_files_except($data['images']);
                $result['images'] = $this->update_filenames($data['images']);
            }
            json_response('ok', 200, $result);
        } catch (\Exception $e) {
            json_response($e->getMessage(), 500);
        }
    }

    /**
     * Creates a new account
     * @param  string $identifier
     * @param  string $password
     * @return void
     */
    public function registerUser(string $identifier, string $password): void
    {
        if (!$identifier || !$password) {
            json_response('Bad query', 400);
            return;
        }
        try {
            $result = [];
            if (create_accountfile($identifier, $password)) {
                $result['identifier'] = $identifier;
            }
            json_response('ok', 200, $result);
        } catch (\Exception $e) {
            json_response($e->getMessage(), 500);
        }
    }

    /**
     * Delete all files except provided list
     * @param  array|null $data \exceptions
     * @return array deleted images filenames list
     * @throws \Exception
     */
    private function delete_all_files_except(?array $data): array
    {
        try {
            if (!$this->imageFolder) {
                throw new \Exception(self::ERROR_NO_IMAGE_FOLDER, 1);
            }
            $images = getImagesInFolder($this->imageFolder);
            $result = [];
            foreach ($images as $image) {
                if (!array_key_exists_in_array_of_arrays($image, 'filename', $data)) {
                    @unlink($this->imageFolder . DS . $image);
                } else {
                    $result[] = [
                        'src' => url(str_replace(ROOT_FOLDER, '', $this->imageFolder) . DS . $image),
                        'filename' => $image
                    ];
                }
            }
            return $result;
        } catch (\Exception $e) {
            throw new \Exception($e->getMessage(), $e->getCode());
        }
    }

    /**
     * Update filenames for given images list
     */
    private function update_filenames(?array $images): array
    {
        try {
            $meta = textFileToArray($this->metaFile);
            if (!$images || !count($images)) {
                return array();
            }
            if (!$this->imageFolder) {
                throw new \Exception(self::ERROR_NO_IMAGE_FOLDER, 1);
            }
            $existingImages = getImagesInFolder($this->imageFolder);
            $result = array();
            foreach ($images as $image) {
                if (array_key_exists('filename', $image) && array_key_exists('newfilename', $image)) {
                    if (in_array($image['filename'], $existingImages)) {
                        $filename = update_filename($this->imageFolder . DS . $image['filename'], $image['newfilename']);
                        $result[] = array(
                            'src' => url(str_replace(ROOT_FOLDER, '', $this->imageFolder) . DS . pathinfo($filename, PATHINFO_FILENAME) . '.' . pathinfo($filename, PATHINFO_EXTENSION)),
                            'filename' => pathinfo($filename, PATHINFO_FILENAME) . '.' . pathinfo($filename, PATHINFO_EXTENSION)
                        );
                    }
                }
            }
            return $result;
        } catch (\Exception $e) {
            throw $e;
        }
    }
}
