# OIDC Provider (OP) - アプリケーション仕様

このディレクトリは、認証基盤である OIDC プロバイダー（OP）のカスタムフロントエンドを担う Rails アプリケーションです。
ユーザープール（Devise）を提供し、Ory Hydra の認証要求・承諾要求に対して対話的なユーザーインターフェースを仲介します。

## 主要機能

1. **認証機能 (User Authentication)**:
   * **Devise** を使用した一般的なパスワード認証。
   * シードデータにより、検証用のテストアカウント (`user@example.com` / `password`) を簡単に投入できます。
2. **Ory Hydra 連携 (Login & Consent Flow)**:
   * `OryHydraService` クラスを通じて Ory Hydra の Admin API (`hydra:4445`) と通信します。
   * **ログインフロー (`LoginController`)**:
     Ory Hydra からログインチャレンジを受け取り、ユーザー認証完了後にチャレンジを承認してリダイレクトします。
   * **同意フロー (`ConsentController`)**:
     ユーザーが要求されたスコープ（`openid`, `profile`, `email` 等）に対して承諾（Allow）または拒否（Reject）を行うための UI を提供します。
3. **OIDC シングルサインアウト対応**:
   * OP 側からユーザーが明示的にサインアウトした際、`ApplicationController#after_sign_out_path_for` を経由して Ory Hydra のパブリックログアウトエンドポイントへ自動的に遷移させます。
   * これにより、Ory Hydra 側に登録されている Relying Party (RP) 宛てにバックチャネルログアウト要求が送信され、システム全体のシングルサインアウトが完了します。

## 開発と実行

起動方法や初期データの投入については、プロジェクトルートの [README.md](../README.md) を参照してください。

### 単体テストの実行

```bash
docker compose exec op bin/rails test
```
主にログインおよび同意フローが正しく Ory Hydra Admin API とやり取りできているかどうかが検証されます。
