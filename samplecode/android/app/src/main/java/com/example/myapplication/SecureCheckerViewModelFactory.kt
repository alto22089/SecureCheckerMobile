package com.example.myapplication

import android.app.Application
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider

// ViewModelに初期値を渡すためのFactoryクラス
class SecureCheckerViewModelFactory(private val apprication: Application, private val initialUrl: String?) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(SecureCheckerViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return SecureCheckerViewModel(apprication,initialUrl) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}