package com.appcloner;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;

import java.util.ArrayList;
import java.util.List;

public class AppAdapter extends RecyclerView.Adapter<AppAdapter.ViewHolder> {

    private List<AppInfo> apps;
    private List<AppInfo> filteredApps;
    private Context context;
    private OnCloneClickListener listener;

    public interface OnCloneClickListener {
        void onCloneClick(AppInfo appInfo);
    }

    public AppAdapter(Context context, List<AppInfo> apps, OnCloneClickListener listener) {
        this.context = context;
        this.apps = apps;
        this.filteredApps = new ArrayList<>(apps);
        this.listener = listener;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(context).inflate(R.layout.item_app, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        AppInfo appInfo = filteredApps.get(position);

        holder.appName.setText(appInfo.name);
        holder.appPackage.setText(appInfo.packageName);
        holder.appVersion.setText("v" + (appInfo.version != null ? appInfo.version : "?"));
        holder.appIcon.setImageDrawable(appInfo.icon);

        holder.cloneButton.setOnClickListener(v -> {
            if (listener != null) {
                listener.onCloneClick(appInfo);
            }
        });
    }

    @Override
    public int getItemCount() {
        return filteredApps.size();
    }

    public void filter(String query) {
        filteredApps.clear();

        if (query.isEmpty()) {
            filteredApps.addAll(apps);
        } else {
            String lowerQuery = query.toLowerCase();
            for (AppInfo app : apps) {
                if (app.name.toLowerCase().contains(lowerQuery) ||
                    app.packageName.toLowerCase().contains(lowerQuery)) {
                    filteredApps.add(app);
                }
            }
        }

        notifyDataSetChanged();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        ImageView appIcon;
        TextView appName;
        TextView appPackage;
        TextView appVersion;
        MaterialButton cloneButton;

        ViewHolder(View itemView) {
            super(itemView);
            appIcon = itemView.findViewById(R.id.appIcon);
            appName = itemView.findViewById(R.id.appName);
            appPackage = itemView.findViewById(R.id.appPackage);
            appVersion = itemView.findViewById(R.id.appVersion);
            cloneButton = itemView.findViewById(R.id.cloneButton);
        }
    }
}
