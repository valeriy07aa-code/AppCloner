package com.appcloner;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

import net.dongliu.apk.parser.bean.ApkMeta;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private RecyclerView recyclerView;
    private AppAdapter adapter;
    private EditText searchEditText;
    private List<AppInfo> allApps = new ArrayList<>();
    private PackageManager packageManager;
    private ArsclibApkCloner apkCloner;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        packageManager = getPackageManager();
        apkCloner = new ArsclibApkCloner(this);

        recyclerView = findViewById(R.id.appsRecyclerView);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));

        searchEditText = findViewById(R.id.searchEditText);
        searchEditText.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                filterApps(s.toString());
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener(v -> showAboutDialog());

        loadApps();
    }

    private void loadApps() {
        new LoadAppsTask().execute();
    }

    private void filterApps(String query) {
        if (adapter != null) {
            adapter.filter(query);
        }
    }

    private void showAboutDialog() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.app_name)
                .setMessage("Клонатор приложений без рекламы.\n\n" +
                        "Возможности:\n" +
                        "• Просмотр установленных приложений\n" +
                        "• Клонирование с изменением package name\n" +
                        "• Установка и шаринг APK\n\n" +
                        "Ограничения:\n" +
                        "• Некоторые приложения могут не работать\n" +
                        "• Банковские приложения требуют оригинальный пакет")
                .setPositiveButton("OK", null)
                .show();
    }

    private void showAppOptionsDialog(AppInfo appInfo) {
        String[] options = {"Клонировать", "Установить оригинал", "Поделиться", "Информация"};

        new MaterialAlertDialogBuilder(this)
                .setTitle(appInfo.name)
                .setItems(options, (dialog, which) -> {
                    switch (which) {
                        case 0:
                            showCloneDialog(appInfo);
                            break;
                        case 1:
                            installOriginal(appInfo);
                            break;
                        case 2:
                            shareApk(appInfo);
                            break;
                        case 3:
                            showAppInfo(appInfo);
                            break;
                    }
                })
                .show();
    }

    private void showCloneDialog(AppInfo appInfo) {
        // Show dialog to enter new package name
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_clone, null);
        EditText packageNameInput = dialogView.findViewById(R.id.packageNameInput);

        // Set default new package name
        packageNameInput.setText(appInfo.packageName + ".clone");

        new MaterialAlertDialogBuilder(this)
                .setTitle("Клонировать " + appInfo.name)
                .setView(dialogView)
                .setPositiveButton("Клонировать", (d, w) -> {
                    String newPackageName = packageNameInput.getText().toString().trim();
                    if (!newPackageName.isEmpty()) {
                        cloneApp(appInfo, newPackageName);
                    } else {
                        Toast.makeText(this, "Введите имя пакета", Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("Отмена", null)
                .show();
    }

    private void cloneApp(AppInfo appInfo, String newPackageName) {
        new CloneTask().execute(appInfo, newPackageName);
    }

    private void installOriginal(AppInfo appInfo) {
        String apkPath = apkCloner.getApkPath(appInfo.packageName);
        if (apkPath != null) {
            apkCloner.installApk(apkPath);
        } else {
            Toast.makeText(this, "APK не найден", Toast.LENGTH_SHORT).show();
        }
    }

    private void shareApk(AppInfo appInfo) {
        String apkPath = apkCloner.getApkPath(appInfo.packageName);
        if (apkPath != null) {
            apkCloner.shareApk(apkPath);
        } else {
            Toast.makeText(this, "APK не найден", Toast.LENGTH_SHORT).show();
        }
    }

    private void showAppInfo(AppInfo appInfo) {
        String apkPath = apkCloner.getApkPath(appInfo.packageName);
        ApkMeta meta = apkCloner.getApkMeta(apkPath);

        StringBuilder info = new StringBuilder();
        info.append("Название: ").append(appInfo.name).append("\n");
        info.append("Пакет: ").append(appInfo.packageName).append("\n");
        info.append("Версия: ").append(appInfo.version).append("\n");

        if (meta != null) {
            info.append("Мин. SDK: ").append(meta.getMinSdkVersion()).append("\n");
            info.append("Целевой SDK: ").append(meta.getTargetSdkVersion()).append("\n");
        }

        info.append("\nПуть: ").append(apkPath);

        new MaterialAlertDialogBuilder(this)
                .setTitle("Информация о приложении")
                .setMessage(info.toString())
                .setPositiveButton("OK", null)
                .show();
    }

    private class LoadAppsTask extends AsyncTask<Void, Void, List<AppInfo>> {

        @Override
        protected List<AppInfo> doInBackground(Void... voids) {
            List<AppInfo> apps = new ArrayList<>();
            List<PackageInfo> packages = packageManager.getInstalledPackages(0);

            for (PackageInfo packageInfo : packages) {
                ApplicationInfo appInfo = packageInfo.applicationInfo;

                // Skip system apps
                if ((appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0) {
                    continue;
                }

                // Skip our own app
                if (packageInfo.packageName.equals(getPackageName())) {
                    continue;
                }

                AppInfo info = new AppInfo();
                info.name = appInfo.loadLabel(packageManager).toString();
                info.packageName = packageInfo.packageName;
                info.version = packageInfo.versionName;
                info.icon = appInfo.loadIcon(packageManager);
                info.sourceDir = appInfo.sourceDir;

                apps.add(info);
            }

            // Sort by name
            Collections.sort(apps, (a1, a2) -> a1.name.compareToIgnoreCase(a2.name));

            return apps;
        }

        @Override
        protected void onPostExecute(List<AppInfo> apps) {
            allApps = apps;
            adapter = new AppAdapter(MainActivity.this, apps, appInfo -> showAppOptionsDialog(appInfo));
            recyclerView.setAdapter(adapter);
        }
    }

    private class CloneTask extends AsyncTask<Object, String, String> {
        private AlertDialog progressDialog;

        @Override
        protected void onPreExecute() {
            View dialogView = LayoutInflater.from(MainActivity.this)
                    .inflate(R.layout.dialog_progress, null);

            progressDialog = new MaterialAlertDialogBuilder(MainActivity.this)
                    .setView(dialogView)
                    .setCancelable(false)
                    .create();
            progressDialog.show();
        }

        @Override
        protected String doInBackground(Object... params) {
            AppInfo appInfo = (AppInfo) params[0];
            String newPackageName = (String) params[1];

            publishProgress("Извлечение APK...");
            try { Thread.sleep(500); } catch (InterruptedException e) {}

            publishProgress("Модификация package name...");
            String result = apkCloner.cloneWithNewPackage(appInfo.packageName, newPackageName);

            publishProgress("Готово!");
            try { Thread.sleep(300); } catch (InterruptedException e) {}

            return result;
        }

        @Override
        protected void onProgressUpdate(String... values) {
            if (progressDialog != null && progressDialog.isShowing()) {
                TextView progressText = progressDialog.findViewById(R.id.progressText);
                if (progressText != null) {
                    progressText.setText(values[0]);
                }
            }
        }

        @Override
        protected void onPostExecute(String result) {
            if (progressDialog != null && progressDialog.isShowing()) {
                progressDialog.dismiss();
            }

            if (result != null) {
                Toast.makeText(MainActivity.this,
                        "Клон создан: " + new File(result).getName(),
                        Toast.LENGTH_LONG).show();

                // Ask if user wants to install
                new MaterialAlertDialogBuilder(MainActivity.this)
                        .setTitle("Установить клон?")
                        .setMessage("Хотите установить клонированное приложение?")
                        .setPositiveButton("Да", (d, w) -> apkCloner.installApk(result))
                        .setNegativeButton("Нет", null)
                        .show();
            } else {
                String errorDetail = apkCloner.getLastError();
                if (errorDetail == null) errorDetail = "Неизвестная ошибка";

                new MaterialAlertDialogBuilder(MainActivity.this)
                        .setTitle("Ошибка клонирования")
                        .setMessage(errorDetail)
                        .setPositiveButton("OK", null)
                        .show();
            }
        }
    }
}
