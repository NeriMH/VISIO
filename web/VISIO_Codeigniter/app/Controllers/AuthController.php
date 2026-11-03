<?php

namespace App\Controllers;

use App\Models\AdminModel;
use App\Models\UsuarioModel;
use App\Models\ResetSenhaAdminModel;

/**
 * AuthController
 * Gerencia login, logout e API de listagem de usuários.
 */
class AuthController extends BaseController
{
     //---------------------------------------------------------------
    // ENDPOINT API (RETORNO JSON)
    // ---------------------------------------------------------------
    public function listarUsuarios()
    {
        $model = new UsuarioModel();
        $usuarios = $model->findAll();

        foreach ($usuarios as &$usuario) {
            unset($usuario['SENHA']);
        }

        return $this->response->setJSON($usuarios);
    }

    // ---------------------------------------------------------------
    // LOGIN DO USUÁRIO COMUM (WEB)
    // ---------------------------------------------------------------

    public function index(): string
    {
        return view('sistema/usuario/login/index');
    }

    public function loginUsuario()
    {
        // Trata requisições enviadas por JSON/AJAX via Fetch
        if ($this->request->isAJAX() || str_contains($this->request->getHeaderLine('Content-Type'), 'json')) {
            $json = $this->request->getJSON();
            $email = $json->email ?? null;
            $senha = $json->senha ?? null;

            if (empty($email) || empty($senha)) {
                return $this->response->setStatusCode(400)->setJSON([
                    'message' => 'E-mail e senha são obrigatórios.'
                ]);
            }

            $model = new UsuarioModel();
            $usuario = $model->buscarPorEmail($email);

            if (!$usuario || !password_verify($senha, $usuario['SENHA'])) {
                return $this->response->setStatusCode(401)->setJSON([
                    'message' => 'E-mail ou senha incorretos.'
                ]);
            }

            session()->set([
                'usuario_logado' => true,
                'usuario_cpf'    => $usuario['CPF'],
                'usuario_email'  => $usuario['EMAIL'],
                'tipo'           => 'usuario',
            ]);

            return $this->response->setJSON([
                'status'  => 200,
                'message' => 'Login realizado com sucesso!'
            ]);
        }

        // Fallback: requisição via FORM tradicional
        $email = $this->request->getPost('email');
        $senha = $this->request->getPost('senha');

        if (empty($email) || empty($senha)) {
            return redirect()->to('/login')
                ->with('erro', 'E-mail e senha são obrigatórios.');
        }

        $model = new UsuarioModel();
        $usuario = $model->buscarPorEmail($email);

        if (!$usuario || !password_verify($senha, $usuario['SENHA'])) {
            return redirect()->to('/login')
                ->with('erro', 'E-mail ou senha incorretos.');
        }

        session()->set([
            'usuario_logado' => true,
            'usuario_cpf'    => $usuario['CPF'],
            'usuario_email'  => $usuario['EMAIL'],
            'tipo'           => 'usuario',
        ]);

        return redirect()->to('/perfil');
    }

   
    public function loginGoogle()
    {
        $credential = $this->request->getPost('credential');

        if (empty($credential)) {
            return redirect()->to('/login')
                ->with('erro', 'Não foi possível entrar com o Google. Tente novamente.');
        }


        $client = \Config\Services::curlrequest();

        try {
            $resposta = $client->get('https://oauth2.googleapis.com/tokeninfo', [
                'query' => ['id_token' => $credential],
                'http_errors' => false,
            ]);
        } catch (\Throwable $e) {
            log_message('error', 'Erro ao verificar ID token do Google: {msg}', ['msg' => $e->getMessage()]);
            return redirect()->to('/login')
                ->with('erro', 'Erro ao verificar o login do Google. Tente novamente.');
        }

        if ($resposta->getStatusCode() !== 200) {
            // Token inválido, expirado ou malformado.
            return redirect()->to('/login')
                ->with('erro', 'Login com Google inválido ou expirado. Tente novamente.');
        }

        $payload = json_decode($resposta->getBody(), true);

        $googleClientId = env('GOOGLE_CLIENT_ID');
        $audienceOk = !empty($googleClientId)
            && ($payload['aud'] ?? null) === $googleClientId;

        $emailVerificado = ($payload['email_verified'] ?? 'false') === 'true';

        if (!$audienceOk || !$emailVerificado || empty($payload['email'])) {
            // 'aud' diferente do nosso Client ID é sinal de um token emitido
            // para outra aplicação — não pode ser aceito aqui.
            return redirect()->to('/login')
                ->with('erro', 'Login com Google inválido. Tente novamente.');
        }

        $model = new UsuarioModel();
        $usuario = $model->buscarPorEmail($payload['email']);

        if (!$usuario) {
            return redirect()->to('/usuario/cadastro')
                ->with('erro', 'Não encontramos uma conta com este e-mail do Google. Complete o cadastro para continuar.');
        }

        session()->set([
            'usuario_logado' => true,
            'usuario_cpf'    => $usuario['CPF'],
            'usuario_email'  => $usuario['EMAIL'],
            'tipo'           => 'usuario',
        ]);

        return redirect()->to('/perfil');
    }

    // ---------------------------------------------------------------
    // LOGIN DO ADMINISTRADOR
    // ---------------------------------------------------------------

    public function loginAdminForm(): string
    {
        return view('sistema/admin/login_adm');
    }

    public function esqueceuSenhaAdmForm(): string
    {
        return view('sistema/admin/esqueceu_senha_adm/index');
    }

   
    public function esqueceuSenhaAdmSolicitar()
    {
        $querJson = $this->request->isAJAX()
            || str_contains($this->request->getHeaderLine('Accept'), 'json')
            || str_contains($this->request->getHeaderLine('Content-Type'), 'json');

        $email = trim($this->request->getPost('email') ?? '');

        if (empty($email)) {
            if ($querJson) {
                return $this->response->setStatusCode(400)->setJSON([
                    'message' => 'Informe um e-mail válido.',
                ]);
            }
            return redirect()->to('/admin/esqueceu_senha')
                ->with('erro', 'Informe um e-mail válido.');
        }

        $adminModel = new AdminModel();
        $admin      = $adminModel->buscarPorEmail($email);

      
        if ($admin) {
            $resetModel = new ResetSenhaAdminModel();
            $resetModel->limparExpirados();
            $token = $resetModel->gerarToken($admin['CNPJ']);

            $link = base_url('/admin/redefinir_senha?token=' . $token);

            if ($querJson) {
                return $this->response->setJSON([
                    'message' => 'E-mail encontrado! Use o link abaixo para redefinir a senha.',
                    'link'    => $link,
                    'token'   => $token,
                ]);
            }

            return view('sistema/admin/esqueceu_senha_adm/token', [
                'link'  => $link,
                'token' => $token,
            ]);
        }

        if ($querJson) {
            return $this->response->setJSON([
                'message' => 'Se o e-mail informado estiver cadastrado, as instruções foram geradas.',
                'link'    => null,
                'token'   => null,
            ]);
        }

        return view('sistema/admin/esqueceu_senha_adm/token', [
            'link'  => null,
            'token' => null,
        ]);
    }

   
    public function redefinirSenhaAdmForm()
    {
        $token = $this->request->getGet('token') ?? '';

        if (empty($token)) {
            return redirect()->to('/admin/esqueceu_senha')
                ->with('erro', 'Token inválido ou ausente.');
        }

        $resetModel = new ResetSenhaAdminModel();
        $registro   = $resetModel->buscarValido($token);

        if (!$registro) {
            return redirect()->to('/admin/esqueceu_senha')
                ->with('erro', 'Este link expirou ou já foi utilizado. Solicite um novo.');
        }

        $adminModel = new AdminModel();
        $admin      = $adminModel->find($registro['FK_CNPJ']);

        return view('sistema/admin/esqueceu_senha_adm/redefinir', [
            'token' => $token,
            'email' => $admin['EMAIL'] ?? '',
        ]);
    }

    public function redefinirSenhaAdmRedefinir()
    {
        $querJson = $this->request->isAJAX()
            || str_contains($this->request->getHeaderLine('Accept'), 'json')
            || str_contains($this->request->getHeaderLine('Content-Type'), 'json');

        $token     = trim($this->request->getPost('token') ?? '');
        $novaSenha = $this->request->getPost('senha') ?? '';
        $confirma  = $this->request->getPost('confirma_senha') ?? '';

        if (empty($token) || empty($novaSenha)) {
            if ($querJson) {
                return $this->response->setStatusCode(400)->setJSON(['message' => 'Preencha todos os campos.']);
            }
            return redirect()->back()
                ->with('erro', 'Preencha todos os campos.');
        }

        if ($novaSenha !== $confirma) {
            if ($querJson) {
                return $this->response->setStatusCode(400)->setJSON(['message' => 'As senhas não coincidem.']);
            }
            return redirect()->back()
                ->with('erro', 'As senhas não coincidem.');
        }

        if (strlen($novaSenha) < 6) {
            if ($querJson) {
                return $this->response->setStatusCode(400)->setJSON(['message' => 'A senha deve ter pelo menos 6 caracteres.']);
            }
            return redirect()->back()
                ->with('erro', 'A senha deve ter pelo menos 6 caracteres.');
        }

        $resetModel = new ResetSenhaAdminModel();
        $registro   = $resetModel->buscarValido($token);

        if (!$registro) {
            if ($querJson) {
                return $this->response->setStatusCode(410)->setJSON(['message' => 'Este link expirou ou já foi utilizado. Solicite um novo.']);
            }
            return redirect()->to('/admin/esqueceu_senha')
                ->with('erro', 'Este link expirou ou já foi utilizado. Solicite um novo.');
        }

        $adminModel = new AdminModel();
        $adminModel->update($registro['FK_CNPJ'], [
            'SENHA' => password_hash($novaSenha, PASSWORD_BCRYPT),
        ]);

        $resetModel->marcarUsado($token);

        if ($querJson) {
            return $this->response->setJSON([
                'message' => 'Senha redefinida com sucesso! Faça login com a nova senha.',
            ]);
        }

        return redirect()->to('/login/admin')
            ->with('sucesso', 'Senha redefinida com sucesso! Faça login com a nova senha.');
    }

    public function loginAdmin()
    {
        if ($this->request->isAJAX() || str_contains($this->request->getHeaderLine('Content-Type'), 'json')) {
            $json = $this->request->getJSON();
            $email = $json->email ?? null;
            $senha = $json->senha ?? null;

            if (empty($email) || empty($senha)) {
                return $this->response->setStatusCode(400)->setJSON([
                    'message' => 'E-mail e senha são obrigatórios.'
                ]);
            }

            $model = new AdminModel();
            $admin = $model->buscarPorEmail($email);

            if (!$admin || !password_verify($senha, $admin['SENHA'])) {
                return $this->response->setStatusCode(401)->setJSON([
                    'message' => 'E-mail ou senha incorretos.'
                ]);
            }

            session()->set([
                'admin_logado' => true,
                'admin_cnpj'   => $admin['CNPJ'],
                'admin_email'  => $admin['EMAIL'],
                'tipo'         => 'admin',
            ]);

            return $this->response->setJSON([
                'status'  => 200,
                'message' => 'Login realizado com sucesso!'
            ]);
        }

        $email = $this->request->getPost('email');
        $senha = $this->request->getPost('senha');

        if (empty($email) || empty($senha)) {
            return redirect()->to('/login/admin')
                ->with('erro', 'E-mail e senha são obrigatórios.');
        }

        $model = new AdminModel();
        $admin = $model->buscarPorEmail($email);

        if (!$admin || !password_verify($senha, $admin['SENHA'])) {
            return redirect()->to('/login/admin')
                ->with('erro', 'E-mail ou senha incorretos.');
        }

        session()->set([
            'admin_logado' => true,
            'admin_cnpj'   => $admin['CNPJ'],
            'admin_email'  => $admin['EMAIL'],
            'tipo'         => 'admin',
        ]);

        return redirect()->to('/admin/dashboard');
    }

    // ---------------------------------------------------------------
    // LOGOUT
    // ---------------------------------------------------------------

    public function logout()
    {
        // O tipo de login precisa ser lido ANTES do destroy(): depois dele a
        // sessão fica vazia e não dá mais para saber se quem saiu era
        // usuário ou administrador.
        $eraAdmin = session()->get('tipo') === 'admin';

        session()->destroy();

        $querJson = $this->request->isAJAX()
            || str_contains($this->request->getHeaderLine('Accept'), 'json');

        if ($querJson) {
            return $this->response->setJSON([
                'status'  => 200,
                'message' => 'Logout realizado com sucesso!',
            ]);
        }

        // Administrador volta para o login de admin; usuário (ou sessão já
        // expirada, sem tipo) volta para o login de usuário.
        return redirect()->to($eraAdmin ? '/login/admin' : '/login');
    }

    public function receberCartao()
    {
        $uid = $this->request->getPost('uid');

        if (empty($uid)) {
            return $this->response->setStatusCode(400)->setJSON([
                'sucesso' => false,
                'mensagem' => 'Cartão não informado.'
            ]);
        }

        $uid = strtoupper(trim($uid));

        $arquivo = WRITEPATH . 'cartao_lido.txt';

        file_put_contents($arquivo, $uid);

        return $this->response->setJSON([
            'sucesso' => true,
            'mensagem' => 'Cartão recebido.'
        ]);
    }

    // public function loginCartao()
    // {
    //     $arquivo = WRITEPATH . 'cartao_lido.txt';

    //     if (!file_exists($arquivo)) {
    //         return $this->response->setJSON([
    //             'autorizado' => false
    //         ]);
    //     }

    //     $uid = trim(file_get_contents($arquivo));

    //     if (empty($uid)) {
    //         return $this->response->setJSON([
    //             'autorizado' => false
    //         ]);
    //     }

    //     file_put_contents($arquivo, '');

    //     $model = new UsuarioModel();

    //     $usuario = $model->where('CARTAO', $uid)->first();

    //     if (!$usuario) {
    //         return $this->response->setJSON([
    //             'autorizado' => false,
    //             'mensagem' => 'Cartão não encontrado.'
    //         ]);
    //     }

    //     session()->set([
    //         'usuario_logado' => true,
    //         'usuario_cpf'    => $usuario['CPF'],
    //         'usuario_email'  => $usuario['EMAIL'],
    //         'tipo'           => 'usuario',
    //     ]);

    //     return $this->response->setJSON([
    //         'autorizado' => true,
    //         'nome'       => $usuario['NOME'],
    //         'cpf'        => $usuario['CPF'],
    //         'redirect'   => base_url('/perfil')
    //     ]);
    // }
    public function loginCartao()
{
    $arquivo = WRITEPATH . 'cartao_lido.txt';

    if (!file_exists($arquivo)) {
        return $this->response->setJSON([
            'autorizado' => false,
            'cartao_lido' => false
        ]);
    }

    $uid = trim(file_get_contents($arquivo));

    if (empty($uid)) {
        return $this->response->setJSON([
            'autorizado' => false,
            'cartao_lido' => false
        ]);
    }

    file_put_contents($arquivo, '');

    $model = new UsuarioModel();

    $usuario = $model->where('CARTAO', $uid)->first();

    if (!$usuario) {
        return $this->response->setJSON([
            'autorizado' => false,
            'cartao_lido' => true,
            'mensagem' => 'Cartão não autorizado.'
        ]);
    }

    session()->set([
        'usuario_logado' => true,
        'usuario_cpf'    => $usuario['CPF'],
        'usuario_email'  => $usuario['EMAIL'],
        'tipo'           => 'usuario',
    ]);

    return $this->response->setJSON([
        'autorizado' => true,
        'cartao_lido' => true,
        'nome'       => $usuario['NOME'],
        'cpf'        => $usuario['CPF'],
        'redirect'   => base_url('/perfil')
    ]);
}
}